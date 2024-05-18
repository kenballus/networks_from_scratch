from tcp import TCPPacket
from ethernet import EthernetFrame, EtherType
from ipv4 import IPv4Packet, IPv4Protocol

INDENT: str = "    "


def prettify_tcp_packet(packet: TCPPacket, indent_level: int) -> str:
    return (
        f"{INDENT * (indent_level + 1)}".join(
            (
                "TCPPacket(\n",
                f"source_port={repr(packet.source_port)},\n",
                f"destination_port={repr(packet.destination_port)},\n",
                f"sequence_number={repr(packet.sequence_number)},\n",
                f"acknowledgment_number={repr(packet.acknowledgment_number)},\n",
                f"data_offset={repr(packet.data_offset)},\n",
                f"reserved={repr(packet.reserved)},\n",
                f"flags={repr(packet.flags)},\n",
                f"window={repr(packet.window)},\n",
                f"checksum={repr(packet.checksum)},\n",
                f"urgent_pointer={repr(packet.urgent_pointer)},\n",
                f"options={packet.options},\n",
                f"data={repr(packet.data)},\n",
            )
        )
        + f"{INDENT * indent_level}).serialize()"
    )

def prettify_ipv4_packet(packet: IPv4Packet, indent_level: int) -> str:
    ip_protocol_name: str
    try:
        ip_protocol_name = IPv4Protocol(packet.protocol).name
    except ValueError:
        ip_protocol_name = "Unknown"

    pretty_payload: str = repr(packet.payload)
    if packet.protocol == IPv4Protocol.TCP.value:
        try:
            pretty_payload = prettify_tcp_packet(TCPPacket.deserialize(packet.payload), indent_level + 1)
        except AssertionError:
            pass

    return (
        f"{INDENT * (indent_level + 1)}".join(
            (
                "IPv4Packet(\n",
                f"version={repr(packet.version)},\n",
                f"ihl={repr(packet.ihl)},\n",
                f"type_of_service={repr(packet.type_of_service)},\n",
                f"total_length={repr(packet.total_length)},\n",
                f"identification={repr(packet.identification)},\n",
                f"flags={repr(packet.flags)},\n",
                f"fragment_offset={repr(packet.fragment_offset)},\n",
                f"time_to_live={repr(packet.time_to_live)},\n",
                f"protocol={repr(packet.protocol)},  # {ip_protocol_name}\n",
                f"header_checksum={repr(packet.header_checksum)},\n",
                f"source_address={repr(packet.source_address)},\n",
                f"destination_address={repr(packet.destination_address)},\n",
                f"options={repr(packet.options)},\n",
                f"payload={pretty_payload},\n",
            )
        )
        + f"{INDENT * indent_level}).serialize()"
    )

def prettify_frame(frame: EthernetFrame, indent_level: int, pkttype: int) -> str:
    direction_symbol: str
    if pkttype == 0:
        direction_symbol = "↑"
    elif pkttype == 1:
        direction_symbol = "*"
    elif pkttype == 4:
        direction_symbol = "↓"
    else:
        direction_symbol = "?"

    ethertype_name: str
    try:
        ethertype_name = EtherType(frame.ethertype).name
    except ValueError:
        ethertype_name = "Unknown"

    pretty_frame_data: str = repr(frame.data)
    if frame.ethertype == EtherType.IPV4.value:
        try:
            pretty_frame_data = prettify_ipv4_packet(IPv4Packet.deserialize(frame.data), indent_level + 1)
        except AssertionError:
            pass

    return (
        f"{INDENT * (indent_level)}"
        + f"{INDENT * (indent_level + 1)}".join(
            (
                f"EthernetFrame(  # {direction_symbol}\n",
                f"destination_address={frame.destination_address},\n",
                f"source_address={frame.source_address},\n",
                f"ethertype={frame.ethertype},  # {ethertype_name}\n",
                f"data={pretty_frame_data},\n",
            )
        )
        + f"{INDENT * (indent_level)})"
    )
