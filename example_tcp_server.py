import random
import sys
import socket
from enum import Enum
from typing import Iterable

import sockets
from ipv4 import IPv4Packet, IPv4Protocol, IPv4Address
from tcp import TCPPacket, TCP_FLAGS_SYN, TCP_FLAGS_ACK, TCP_FLAGS_PSH


def get_ipv4_packets(sock: socket.socket) -> Iterable[IPv4Packet | None]:
    """
    Returns an iterable of the IPv4Packets incoming on the socket.
    None will be inserted in the iterable if a socket timeout occurs.
    """
    def result():
        while True:
            try:
                data, _address = sock.recvfrom(sockets.RECV_SIZE)
                yield IPv4Packet.deserialize(data)
            except (BlockingIOError, TimeoutError):
                yield None

    return result()


def get_tcp_packets(ipv4_packets: Iterable[IPv4Packet | None]) -> Iterable[tuple[TCPPacket, IPv4Address] | None]:
    """
    Returns an iterable of the TCP packets from the ipv4 packets.
    If any of the ipv4 packets are None, they are left as-is.
    """
    def result():
        for ipv4_packet in ipv4_packets:
            if ipv4_packet is None:
                yield None
            elif ipv4_packet.protocol == IPv4Protocol.TCP.value:
                try:
                    yield (TCPPacket.deserialize(ipv4_packet.payload), ipv4_packet.source_address)
                except AssertionError:
                    pass

    return result()


class TCPServerState(Enum):
    LISTENING = 0
    SYN_RECEIVED = 1
    ESTABLISHED = 2


WINDOW_SIZE: int = 33280
NUM_TCP_RETRIES: int = 3
TCP_TIMEOUT: float = 1.0  # Seconds


def construct_synack(syn: TCPPacket, source_address: IPv4Address, peer_address: IPv4Address) -> TCPPacket:
    assert syn.flags.syn and not syn.flags.ack
    result: TCPPacket = TCPPacket(
        syn.destination_port,
        syn.source_port,
        random.randint(0, 2**32 - 1),
        (syn.sequence_number + len(syn.data) + syn.flags.syn) % 2**32,
        0,
        0,
        TCP_FLAGS_SYN | TCP_FLAGS_ACK,
        WINDOW_SIZE,
        0,
        0,
        [],
        b"",
    )
    result.fix_padding()
    result.fix_data_offset()
    result.fix_checksum(source_address, peer_address)
    return result


def tcp_roundtrip(
    outgoing_pkt: TCPPacket,
    source_address: IPv4Address,
    peer_address: IPv4Address,
    sock: socket.socket,
    incoming_packets_on_connection: Iterable[TCPPacket | None],
) -> TCPPacket | None:
    """
    Send a TCP packet and return the packet ACKing it.
    If no ACK is sent within the timeout period, or a RST is received, return None
    """
    for _ in range(NUM_TCP_RETRIES):
        sock.sendto(
            IPv4Packet.default(
                source_address, peer_address, IPv4Protocol.TCP, outgoing_pkt.serialize()
            ).serialize(),
            (str(peer_address), 0),
        )  # The 0 is ignored.

        sock.settimeout(TCP_TIMEOUT)
        incoming_pkt: TCPPacket | None = next(
            filter(
                lambda p: p is None or (
                    p.acknowledgment_number == (outgoing_pkt.sequence_number + len(outgoing_pkt.data) + outgoing_pkt.flags.syn) % 2**32
                )
                or p.flags.rst,
                incoming_packets_on_connection,
            ),
        )
        # Timeout occurred
        if incoming_pkt is None:
            continue
        # Connection reset
        if incoming_pkt.flags.rst:
            incoming_pkt = None
        break

    sock.settimeout(None)
    return incoming_pkt


def handle_connection(source_address: IPv4Address, source_port: int, data_to_send: bytes) -> None:
    sock: socket.socket = sockets.make_ethernet_socket(IPv4Protocol.TCP.value)
    packets_with_matching_port: Iterable[tuple[TCPPacket, IPv4Address] | None] = filter(
        lambda t: t is None or t[0].destination_port == source_port, get_tcp_packets(get_ipv4_packets(sock))
    )

    # Listen until you hit a syn for the right port
    syn: TCPPacket
    for pkt_and_address in packets_with_matching_port:
        assert pkt_and_address is not None
        pkt, peer_address = pkt_and_address
        if pkt.flags.syn and not pkt.flags.ack:
            syn = pkt
            break
    print("Received SYN!")

    # All the packets with the right source address, dst port, and src port
    incoming_packets_on_connection: Iterable[TCPPacket | None] = (
        None if t is None else t[0]
        for t in packets_with_matching_port
        if t is None or (t[1] == peer_address and t[0].source_port == syn.source_port)
    )

    print("Sending SYNACK...")
    ack: TCPPacket | None = tcp_roundtrip(
        construct_synack(pkt, source_address, peer_address),
        source_address,
        peer_address,
        sock,
        incoming_packets_on_connection,
    )
    if ack is None:
        print("Connection failed!")
        return
    print("Received ACK!")

    last_ack: TCPPacket = ack
    chunk_size: int = 1024
    num_chunks: int = len(data_to_send) // chunk_size
    for i, chunk in enumerate(data_to_send[i:i + chunk_size] for i in range(0, len(data_to_send), chunk_size)):
        response: TCPPacket = TCPPacket(
            source_port=source_port,
            destination_port=ack.source_port,
            sequence_number=last_ack.acknowledgment_number,
            acknowledgment_number=last_ack.sequence_number + len(last_ack.data),
            data_offset=0,
            reserved=0,
            flags=TCP_FLAGS_ACK | TCP_FLAGS_PSH,
            window=WINDOW_SIZE,
            checksum=0,
            urgent_pointer=0,
            options=[],
            data=chunk,
        )
        response.fix_padding()
        response.fix_data_offset()
        response.fix_checksum(source_address, peer_address)

        received_ack = tcp_roundtrip(
            response,
            source_address,
            peer_address,
            sock,
            incoming_packets_on_connection,
        )
        if received_ack is None:
            print("Data sent but not ACKed!")
            break
        last_ack = received_ack
        print(f"Sent data chunk {i}/{num_chunks}")
    print("Closing connection.")


def main() -> None:
    if len(sys.argv) != 4:
        print("Usage: python3 {sys.argv[0]} <bind_address> <port> <file>", file=sys.stderr)
        print("    bind_address: The source address of outgoing IP packets.", file=sys.stderr)
        print("    port: The source port of outgoing TCP packets.", file=sys.stderr)
        print("    file: The file to serve.", file=sys.stderr)
        sys.exit(1)

    source_address: IPv4Address = IPv4Address(sys.argv[1])
    source_port: int = int(sys.argv[2])
    with open(sys.argv[3], "rb") as f:
        data_to_send: bytes = f.read()

    while True:
        handle_connection(source_address, source_port, data_to_send)


if __name__ == "__main__":
    main()
