import sockets

from icmp import ICMPEchoMessage, ICMPMessageTypes
from ip import IPv4Packet, IPFlags, IPv4Address, IPProtocol, NULL_IPTOS
from ethernet import MACAddress, EtherType, EthernetFrame
from tcp import TCPPacket,ConstructTCPOption


example_tcp_syn: TCPPacket = TCPPacket(
    0x0000,  # Source port                <- add
    0x0050,  # Destination port
    0x00000000,  # Sequence number        <- add
    0x00000000,  # Acknowledgment number
    0xA,  # Data offset
    0,  # Reserved
    TCP_FLAGS_SYN,
    0x0000, # window                     <- add
    0x0000, # checksum                   <- add
    0x0000, # urgent_pointer
    [
        ConstructTCPOption.max_segment_size(b"\x05\xb4"),
        ConstructTCPOption.sack_permitted(),
        ConstructTCPOption.timestamps(b"\xd7\xcc\xea\x4b", b"\x00\x00\x00\x00"),
        ConstructTCPOption.no_operation(),
        ConstructTCPOption.window_scale(b"\x07"),
    ],
    b"",
)


def main() -> None:
    # We're going to make an ICMP echo (ping) packet from scratch.
    icmp_packet: ICMPEchoMessage = ICMPEchoMessage(
        ICMPMessageTypes.ECHO.value,
        0,  # Code
        0,  # Checksum
        0,  # Identifier
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
        IPv4Address("127.0.0.1"),  # Source IP
        IPv4Address("127.0.0.2"),  # Destination IP
        [],  # Options
        icmp_packet.serialize(),  # Payload
    )
    ip_packet.fix()  # Fix the padding, IHL, total length, and checksum

    # This is the ethernet frame. Note that its payload is the IP packet.
    ethernet_frame: EthernetFrame = EthernetFrame(
        MACAddress("00:00:00:00:00:00"),  # Destination MAC
        MACAddress("00:00:00:00:00:00"),  # Source MAC
        EtherType.IP.value,
        ip_packet.serialize(),
    )

    # Send the IP packet to localhost (i.e., on the loopback interface).
    eth_sock = sockets.make_ethernet_socket()
    serialized_ip_packet = ip_packet.serialize()
    assert eth_sock.sendto(serialized_ip_packet, ("localhost", 0)) == len(serialized_ip_packet)

    # Send the ethernet frame on the loopback interface.
    raw_sock = sockets.make_raw_socket()
    serialized_ethernet_frame = ethernet_frame.serialize()
    assert raw_sock.sendto(serialized_ethernet_frame, ("lo", 0)) == len(serialized_ethernet_frame)


if __name__ == "__main__":
    main()
