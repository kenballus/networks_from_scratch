import socket


def make_raw_socket() -> socket.socket:
    """Nothing abstracted away"""
    result: socket.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    return result


def make_ethernet_socket() -> socket.socket:
    """Ethernet abstracted away"""
    result: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    result.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return result
