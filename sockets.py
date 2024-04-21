import socket

from typing import Final

ETH_P_ALL: Final[int] = 3

RECV_SIZE: Final[int] = 65536


def make_raw_socket() -> socket.socket:
    """Makes a socket into which you can write ethernet frames."""
    result: socket.socket = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
    )
    return result


def make_ethernet_socket() -> socket.socket:
    """Makes a socket into which you can write IP packets."""
    result: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    result.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return result


def flush_socket(s: socket.socket) -> None:
    """Removes everything in the socket buffer from before this function was called.
    There is no guarantee that data received during the execution of this function
    will be flushed.
    """
    orig_timeout: float | None = s.gettimeout()
    s.settimeout(0.0)
    while True:
        try:
            s.recv(RECV_SIZE)
        except BlockingIOError:
            break
    s.settimeout(orig_timeout)
