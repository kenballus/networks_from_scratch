import sockets

from ip import IPv4Packet, IPFlags, IPv4Address, IPProtocol
from ethernet import MACAddress, EtherType, EthernetFrame

# We're going to make an IP packet and encapsulating ethernet frame from scratch.

# This is the payload of the IP packet. We're starting with an empty payload.
payload: bytes = b""

# This is the number of 32-bit words in the IP header.
# It would be 6 if we were using IP options.
ip_header_words: int = 5

# This is the IP packet.
packet: IPv4Packet = IPv4Packet(
    4,  # Version
    ip_header_words,  # IHL
    0,  # ToS
    ip_header_words * 4 + len(payload),  # Total length
    0,  # ID
    IPFlags(False, False, False),
    0,  # Fragment
    64,  # TTL
    IPProtocol.ICMP.value,  # Protocol
    0,  # Checksum
    IPv4Address("127.0.0.1"),  # Source IP
    IPv4Address("127.0.0.1"),  # Destination IP
)

# This is the ethernet frame. Note that its payload is the IP packet.
frame: EthernetFrame = EthernetFrame(
    MACAddress("00:00:00:00:00:00"),  # Destination MAC
    MACAddress("00:00:00:00:00:00"),  # Source MAC
    EtherType.IP.value,
    packet.serialize(),
)

# We're sending the ethernet frame on the loopback interface.
raw_sock = sockets.make_raw_socket()
raw_sock.sendto(frame.serialize(), ("lo", 0))

# We're sending the IP packet to localhost (i.e., also on the loopback interface).
eth_sock = sockets.make_ethernet_socket()
eth_sock.sendto(packet.serialize(), ("localhost", 0))

# If you're watching the loopback interface with tcpdump (e.g. with `tcpdump -nXXvvv -i lo`),
# then you should see roughly the same IP packet transmitted, except for the ID and checksum.
