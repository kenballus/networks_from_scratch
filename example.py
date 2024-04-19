import random
import sys
import sockets

from icmp import ICMPEchoMessage, ICMPMessageTypes
from ip import IPv4Packet, IPFlags, IPv4Address, IPProtocol, NULL_IPTOS
from ethernet import MACAddress, EtherType, EthernetFrame
from tcp import TCPPacket, TCP_FLAGS_SYN


def syn(
    interface: str,
    source_mac: MACAddress,
    gateway_mac: MACAddress,
    source_ip: IPv4Address,
    destination_ip: IPv4Address,
) -> None:
    tcp_syn_packet: TCPPacket = TCPPacket(
        random.randint(1024, 65535),  # Source port
        80,  # Destination port
        0,  # Sequence number
        0,  # Acknowledgment number
        0,  # Data offset
        0,  # Reserved
        TCP_FLAGS_SYN,
        0,  # window
        0,  # checksum
        0,  # urgent_pointer
        [],
        b"",
    )
    tcp_syn_packet.fix_padding()
    tcp_syn_packet.fix_data_offset()
    tcp_syn_packet.fix_checksum(destination_ip, source_ip)

    # This is the IP packet.
    ip_packet: IPv4Packet = IPv4Packet(
        4,  # Version
        0,  # IHL
        NULL_IPTOS,  # ToS
        0,  # Total length
        0,  # ID
        IPFlags(False, True, False),
        0,  # Fragment
        64,  # TTL
        IPProtocol.TCP.value,  # Protocol
        0,  # Checksum
        source_ip,
        destination_ip,
        [],  # Options
        tcp_syn_packet.serialize(),  # Payload
    )
    ip_packet.fix()  # Fix the padding, IHL, total length, and checksum

    # This is the ethernet frame. Note that its payload is the IP packet.
    ethernet_frame: EthernetFrame = EthernetFrame(
        gateway_mac,
        source_mac,
        EtherType.IP.value,
        ip_packet.serialize(),
    )

    # Send the ethernet frame on the loopback interface.
    raw_sock = sockets.make_raw_socket()
    serialized_ethernet_frame = ethernet_frame.serialize()
    assert raw_sock.sendto(serialized_ethernet_frame, (interface, 0)) == len(
        serialized_ethernet_frame
    )


def ping(
    interface: str,
    source_mac: MACAddress,
    gateway_mac: MACAddress,
    source_ip: IPv4Address,
    destination_ip: IPv4Address,
) -> None:
    # We're going to make an ICMP echo (ping) packet from scratch.
    icmp_packet: ICMPEchoMessage = ICMPEchoMessage(
        ICMPMessageTypes.ECHO.value,
        0,  # Code
        0,  # Checksum
        1,  # Identifier
        0,  # Sequence number
        bytes(range(0x38)),
    )
    icmp_packet.fix()  # Fix the checksum

    # This is the IP packet.
    ip_packet: IPv4Packet = IPv4Packet(
        4,  # Version
        0,  # IHL
        NULL_IPTOS,  # ToS
        0,  # Total length
        0,  # ID
        IPFlags(False, True, False),
        0,  # Fragment
        64,  # TTL
        IPProtocol.ICMP.value,  # Protocol
        0,  # Checksum
        source_ip,
        destination_ip,
        [],  # Options
        icmp_packet.serialize(),  # Payload
    )
    ip_packet.fix()  # Fix the padding, IHL, total length, and checksum

    # This is the ethernet frame. Note that its payload is the IP packet.
    ethernet_frame: EthernetFrame = EthernetFrame(
        gateway_mac,
        source_mac,
        EtherType.IP.value,
        ip_packet.serialize(),
    )

    # Send the ethernet frame on the loopback interface.
    raw_sock = sockets.make_raw_socket()
    serialized_ethernet_frame = ethernet_frame.serialize()
    assert raw_sock.sendto(serialized_ethernet_frame, (interface, 0)) == len(
        serialized_ethernet_frame
    )


if __name__ == "__main__":
    if len(sys.argv) != 6:
        print(
            f"Usage: python3 {sys.argv[0]} <interface> <source_mac> <gateway_mac> <source_ip> <destination_ip>",
            file=sys.stderr,
        )
    syn(
        sys.argv[1],
        MACAddress(sys.argv[2]),
        MACAddress(sys.argv[3]),
        IPv4Address(sys.argv[4]),
        IPv4Address(sys.argv[5]),
    )
