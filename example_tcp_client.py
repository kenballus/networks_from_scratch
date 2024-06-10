import random
import sys
import socket
from enum import Enum
from typing import Iterable

import sockets
from ipv4 import IPv4Packet, IPv4Protocol, IPv4Address, IPV4TOS_NULL, IPv4Flags
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


def get_tcp_packets(
    ipv4_packets: Iterable[IPv4Packet | None],
) -> Iterable[tuple[TCPPacket, IPv4Address] | None]:
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


WINDOW_SIZE: int = 33280
NUM_TCP_RETRIES: int = 3
TCP_TIMEOUT: float = 1.0  # Seconds


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
                lambda p: p is None
                or (
                    p.acknowledgment_number
                    == (outgoing_pkt.sequence_number + len(outgoing_pkt.data) + outgoing_pkt.flags.syn)
                    % 2**32
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


def main() -> None:
    if len(sys.argv) != 4:
        print(
            f"Usage: python3 {sys.argv[0]} <source_address> <desination_address> <destination_port>",
            file=sys.stderr,
        )
        print("    source_address: The source address of the outgoing packets.", file=sys.stderr)
        print("    destination_address: The desination address of the outgoing packets.")
        print("    port: The destination port of the outgoing packets.", file=sys.stderr)
        sys.exit(1)

    source_address: IPv4Address = IPv4Address(sys.argv[1])
    destination_address: IPv4Address = IPv4Address(sys.argv[1])
    destination_port: int = int(sys.argv[3])
    source_port: int = random.randint(1024, 65535)  # If this collides, the client will fail.

    sock: socket.socket = sockets.make_ethernet_socket(IPv4Protocol.TCP.value)

    syn: TCPPacket = TCPPacket(
        source_port,
        destination_port,  # Destination port
        random.randint(0, 2**32 - 1),  # Sequence number
        0,  # Acknowledgment number
        0,  # Data offset
        0,  # Reserved
        TCP_FLAGS_SYN,
        WINDOW_SIZE,  # window
        0,  # checksum
        0,  # urgent_pointer
        [],
        b"",
    )
    syn.fix_padding()
    syn.fix_data_offset()
    syn.fix_checksum(source_address, destination_address)

    sock.sendto(
        IPv4Packet.default(
            source_address, destination_address, IPv4Protocol.TCP, syn.serialize()
        ).serialize(),
        (str(destination_address), 0),
    )
    for pkt_and_address in get_tcp_packets(get_ipv4_packets(sock)):
        assert pkt_and_address is not None
        pkt, address = pkt_and_address
        if (
            address == destination_address
            and pkt.source_port == syn.destination_port
            and pkt.destination_port == syn.source_port
        ):
            synack = pkt
            break

    ack: TCPPacket = TCPPacket(
        source_port,
        destination_port,  # Destination port
        synack.acknowledgment_number,
        (synack.sequence_number + 1) % 2**32,  # Acknowledgment number
        0,  # Data offset
        0,  # Reserved
        TCP_FLAGS_ACK,
        WINDOW_SIZE,  # window
        0,  # checksum
        0,  # urgent_pointer
        [],
        b"",
    )
    ack.fix_padding()
    ack.fix_data_offset()
    ack.fix_checksum(source_address, destination_address)

    sock.sendto(
        IPv4Packet.default(
            source_address, destination_address, IPv4Protocol.TCP, ack.serialize()
        ).serialize(),
        (str(destination_address), 0),
    )

    req: TCPPacket = TCPPacket(
        source_port,
        destination_port,  # Destination port
        ack.sequence_number,
        ack.acknowledgment_number,
        0,  # Data offset
        0,  # Reserved
        TCP_FLAGS_PSH | TCP_FLAGS_ACK,
        WINDOW_SIZE,  # window
        0,  # checksum
        0,  # urgent_pointer
        [],
        b"GET / HTTP/1.1\r\n\r\n",
    )
    req.fix_padding()
    req.fix_data_offset()
    req.fix_checksum(source_address, destination_address)
    sock.sendto(
        IPv4Packet.default(
            source_address, destination_address, IPv4Protocol.TCP, req.serialize()
        ).serialize(),
        (str(destination_address), 0),
    )

    for pkt_and_address in get_tcp_packets(get_ipv4_packets(sock)):
        assert pkt_and_address is not None
        pkt, address = pkt_and_address
        if (
            address == destination_address
            and pkt.source_port == syn.destination_port
            and pkt.destination_port == syn.source_port
        ):
            if pkt.flags.fin:
                break # Would be better to actually close the connection
            sys.stdout.buffer.write(pkt.data)
            data_ack: TCPPacket = TCPPacket(
                source_port,
                destination_port,  # Destination port
                (req.acknowledgment_number + len(req.data)) % 2**32,
                (pkt.sequence_number + len(pkt.data)) % 2**32,  # Acknowledgment number
                0,  # Data offset
                0,  # Reserved
                TCP_FLAGS_ACK,
                WINDOW_SIZE,  # window
                0,  # checksum
                0,  # urgent_pointer
                [],
                b"",
            )
            data_ack.fix_padding()
            data_ack.fix_data_offset()
            data_ack.fix_checksum(source_address, destination_address)
            sock.sendto(
                IPv4Packet.default(
                    source_address, destination_address, IPv4Protocol.TCP, data_ack.serialize()
                ).serialize(),
                (str(destination_address), 0),
            )

if __name__ == "__main__":
    main()
