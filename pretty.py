from tcp import TCPPacket
from tcp_options import TCPOption
from ethernet import EthernetFrame, EtherType
from ipv4 import IPv4Packet, IPv4Protocol

INDENT: str = "    "


def prettify_tcp_option(option: TCPOption, indent_level: int) -> str:
    return f"{INDENT * indent_level}TCPOption(option_kind={repr(option.option_kind)}, option_length={repr(option.option_length)}, option_data={repr(option.option_data)})"


def prettify_tcp_packet(packet: TCPPacket, indent_level: int) -> str:
    pretty_options: str = (
        f"[\n{',\n'.join(prettify_tcp_option(op, indent_level + 2) for op in packet.options)}\n{INDENT * (indent_level + 1)}]"
        if len(packet.options) > 0
        else "[]"
    )
    return (
        f"\n{INDENT * (indent_level + 1)}".join(
            (
                "TCPPacket(",
                f"source_port={repr(packet.source_port)},",
                f"destination_port={repr(packet.destination_port)},",
                f"sequence_number={repr(packet.sequence_number)},",
                f"acknowledgment_number={repr(packet.acknowledgment_number)},",
                f"data_offset={repr(packet.data_offset)},",
                f"reserved={repr(packet.reserved)},",
                f"flags={repr(packet.flags)},",
                f"window={repr(packet.window)},",
                f"checksum={repr(packet.checksum)},",
                f"urgent_pointer={repr(packet.urgent_pointer)},",
                f"options={pretty_options},",
                f"data={repr(packet.data)},\n",
            )
        )
        + f"{INDENT * indent_level})"
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
            pretty_payload = (
                prettify_tcp_packet(TCPPacket.deserialize(packet.payload), indent_level + 1) + ".serialize()"
            )
        except AssertionError:
            pass

    return (
        f"\n{INDENT * (indent_level + 1)}".join(
            (
                "IPv4Packet(",
                f"version={repr(packet.version)},",
                f"ihl={repr(packet.ihl)},",
                f"type_of_service={repr(packet.type_of_service)},",
                f"total_length={repr(packet.total_length)},",
                f"identification={repr(packet.identification)},",
                f"flags={repr(packet.flags)},",
                f"fragment_offset={repr(packet.fragment_offset)},",
                f"time_to_live={repr(packet.time_to_live)},",
                f"protocol={repr(packet.protocol)},  # {ip_protocol_name}",
                f"header_checksum={repr(packet.header_checksum)},",
                f"source_address={repr(packet.source_address)},",
                f"destination_address={repr(packet.destination_address)},",
                f"options={repr(packet.options)},",
                f"payload={pretty_payload},\n",
            )
        )
        + f"{INDENT * indent_level})"
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
            pretty_frame_data = (
                prettify_ipv4_packet(IPv4Packet.deserialize(frame.data), indent_level + 1) + ".serialize()"
            )
        except AssertionError:
            pass

    return (
        f"{INDENT * (indent_level)}"
        + f"\n{INDENT * (indent_level + 1)}".join(
            (
                f"EthernetFrame(  # {direction_symbol}",
                f"destination_address={frame.destination_address},",
                f"source_address={frame.source_address},",
                f"ethertype={frame.ethertype},  # {ethertype_name}",
                f"data={pretty_frame_data},\n",
            )
        )
        + f"{INDENT * (indent_level)})"
    )
