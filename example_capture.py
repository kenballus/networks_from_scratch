import sys
import sockets

from ethernet import EthernetFrame, EtherType
from ipv4 import IPv4Packet


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
        if pkttype == 0:
            print("↑", end=" ")
        elif pkttype == 1:
            # print("*", end=" ")
            continue
        elif pkttype == 4:
            print("↓", end=" ")

        ip_packet: IPv4Packet | None = None
        if frame.ethertype == EtherType.IPV4.value:
            try:
                ip_packet = IPv4Packet.deserialize(frame.data)
            except AssertionError:
                pass

        frame_data: str = repr(frame.data)
        if ip_packet is not None:
            frame_data = repr(ip_packet) + ".serialize()"

        ethertype_name: str
        try:
            ethertype_name = EtherType(frame.ethertype).name
        except ValueError:
            ethertype_name = "Unknown"

        print(f"EthernetFrame(\n    {frame.destination_address},\n    {frame.source_address},\n    {frame.ethertype},  # {ethertype_name}\n    {frame_data}\n)")



if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print(
            f"Usage: python3 {sys.argv[0]} <interface> [timeout]",
            file=sys.stderr,
        )
    capture(sys.argv[1], float(sys.argv[2]) if len(sys.argv) == 3 else None)
