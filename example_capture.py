import sys
import sockets

from ethernet import EthernetFrame, EtherType
from ipv4 import IPv4Packet, IPv4Protocol


INDENT: str = "    "


def capture(interface: str, timeout: float | None) -> None:
    sock = sockets.make_raw_socket()
    sock.bind((interface, sockets.ETH_P_ALL))
    sockets.flush_socket(sock)

    sock.settimeout(timeout)
    while True:
        try:
            data, address = sock.recvfrom(sockets.RECV_SIZE)
        except TimeoutError:
            break
        frame: EthernetFrame = EthernetFrame.deserialize(data)
        pkttype: int = address[2]
        direction_symbol: str
        if pkttype == 0:
            direction_symbol = "↑"
        elif pkttype == 1:
            direction_symbol = "*"
        elif pkttype == 4:
            direction_symbol = "↓"
        else:
            direction_symbol = "?"

        ip_packet: IPv4Packet | None = None
        if frame.ethertype == EtherType.IPV4.value:
            try:
                ip_packet = IPv4Packet.deserialize(frame.data)
            except AssertionError:
                pass

        frame_data: str = repr(frame.data)
        if ip_packet is not None:
            ip_protocol_name: str
            try:
                ip_protocol_name = IPv4Protocol(ip_packet.protocol).name
            except ValueError:
                ip_protocol_name = "Unknown"
            frame_data = (
                f"{INDENT * 2}".join(
                    (
                        "IPv4Packet(\n",
                        f"version={repr(ip_packet.version)},\n",
                        f"ihl={repr(ip_packet.ihl)},\n",
                        f"type_of_service={repr(ip_packet.type_of_service)},\n",
                        f"total_length={repr(ip_packet.total_length)},\n",
                        f"identification={repr(ip_packet.identification)},\n",
                        f"flags={repr(ip_packet.flags)},\n",
                        f"fragment_offset={repr(ip_packet.fragment_offset)},\n",
                        f"time_to_live={repr(ip_packet.time_to_live)},\n",
                        f"protocol={repr(ip_packet.protocol)},  # {ip_protocol_name}\n",
                        f"header_checksum={repr(ip_packet.header_checksum)},\n",
                        f"source_address={repr(ip_packet.source_address)},\n",
                        f"destination_address={repr(ip_packet.destination_address)},\n",
                        f"options={repr(ip_packet.options)},\n",
                        f"payload={repr(ip_packet.payload)},\n",
                    )
                )
                + f"{INDENT}).serialize(),"
            )

        ethertype_name: str
        try:
            ethertype_name = EtherType(frame.ethertype).name
        except ValueError:
            ethertype_name = "Unknown"

        print(
            f"{INDENT}".join(
                (
                    f"EthernetFrame(  # {direction_symbol}\n",
                    f"destination_address={frame.destination_address},\n",
                    f"source_address={frame.source_address},\n",
                    f"ethertype={frame.ethertype},  # {ethertype_name}\n",
                    f"data={frame_data}\n",
                )
            )
            + ")"
        )


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print(
            f"Usage: python3 {sys.argv[0]} <interface> [timeout]",
            file=sys.stderr,
        )
    capture(sys.argv[1], float(sys.argv[2]) if len(sys.argv) == 3 else None)
