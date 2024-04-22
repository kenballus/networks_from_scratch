import random
import sys
import sockets

from icmp import ICMPEchoMessage, ICMPMessageTypes
from ipv4 import IPv4Packet, IPv4Flags, IPv4Address, IPv4Protocol, IPV4TOS_NULL
from ethernet import MACAddress, EtherType, EthernetFrame


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
        random.randint(0, 0xFFFF),  # Identifier
        0,  # Sequence number
        bytes(range(0x38)),
    )
    icmp_packet.fix()  # Fix the checksum

    # This is the IP packet.
    ip_packet: IPv4Packet = IPv4Packet(
        4,  # Version
        0,  # IHL
        IPV4TOS_NULL,  # ToS
        0,  # Total length
        0,  # ID
        IPv4Flags(False, True, False),
        0,  # Fragment
        64,  # TTL
        IPv4Protocol.ICMP.value,  # Protocol
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
        EtherType.IPV4.value,
        ip_packet.serialize(),
    )

    sock = sockets.make_raw_socket()
    sock.bind((interface, sockets.ETH_P_ALL))
    sockets.flush_socket(sock)
    serialized_ethernet_frame = ethernet_frame.serialize()
    assert sock.send(serialized_ethernet_frame) == len(serialized_ethernet_frame)


if __name__ == "__main__":
    if len(sys.argv) != 6:
        print(
            f"Usage: python3 {sys.argv[0]} <interface> <source_mac> <gateway_mac> <source_ip> <destination_ip>",
            file=sys.stderr,
        )
    ping(
        sys.argv[1],
        MACAddress(sys.argv[2]),
        MACAddress(sys.argv[3]),
        IPv4Address(sys.argv[4]),
        IPv4Address(sys.argv[5]),
    )
