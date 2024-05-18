import sys
import sockets

from pretty import prettify_frame

from ethernet import EthernetFrame, EtherType
from ipv4 import IPv4Packet, IPv4Protocol
from tcp import TCPPacket


def capture(interface: str) -> None:
    sock = sockets.make_raw_socket()
    sock.bind((interface, sockets.ETH_P_ALL))
    sockets.flush_socket(sock)

    while True:
        try:
            data, address = sock.recvfrom(sockets.RECV_SIZE)
        except TimeoutError:
            break
        frame: EthernetFrame = EthernetFrame.deserialize(data)

        print(prettify_frame(frame, 0, data[2]))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            f"Usage: python3 {sys.argv[0]} <interface>",
            file=sys.stderr,
        )
        sys.exit(1)
    capture(sys.argv[1])
