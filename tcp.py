from dataclasses import dataclass

import tcp_options

from ip import IPv4Address, IPProtocol
from tcp_options import TCPOption

from util import bitfield, int_to_bytes, checksum


@dataclass
class TCPFlags:
    ece: bool
    cwr: bool
    urg: bool
    ack: bool
    psh: bool
    rst: bool
    syn: bool
    fin: bool

    def serialize(self) -> int:
        return bitfield(
            self.ece,
            self.cwr,
            self.urg,
            self.ack,
            self.psh,
            self.rst,
            self.syn,
            self.fin,
        )

    def __or__(self, other):
        if not isinstance(other, TCPFlags):
            return NotImplemented
        return TCPFlags(
            self.ece | other.ece,
            self.cwr | other.cwr,
            self.urg | other.urg,
            self.ack | other.ack,
            self.psh | other.psh,
            self.rst | other.rst,
            self.syn | other.syn,
            self.fin | other.fin,
        )


TCP_FLAGS_SYN: TCPFlags = TCPFlags(False, False, False, False, False, False, True, False)


@dataclass
class TCPPacket:
    """
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |       |C|E|U|A|P|R|S|F|                               |
    | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
    |       |       |R|E|G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           [Options]                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               :
    :                             Data                              :
    :                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    source_port: int
    destination_port: int
    sequence_number: int
    acknowledgment_number: int
    data_offset: int
    reserved: int
    flags: TCPFlags
    window: int
    checksum: int
    urgent_pointer: int
    options: list[TCPOption]
    data: bytes

    def __post_init__(self) -> None:
        assert all(
            (
                0 <= self.source_port < 2**16,
                0 <= self.destination_port < 2**16,
                0 <= self.sequence_number < 2**32,
                0 <= self.acknowledgment_number < 2**32,
                0 <= self.data_offset < 2**4,
                0 <= self.reserved < 2**4,
                0 <= self.window < 2**16,
                0 <= self.checksum < 2**16,
                0 <= self.urgent_pointer < 2**16,
            )
        )

    def serialize(self) -> bytes:
        return b"".join(
            (
                int_to_bytes(self.source_port, 2),
                int_to_bytes(self.destination_port, 2),
                int_to_bytes(self.sequence_number, 4),
                int_to_bytes(self.acknowledgment_number, 4),
                bytes([(self.data_offset << 4) | self.reserved, self.flags.serialize()]),
                int_to_bytes(self.window, 2),
                int_to_bytes(self.checksum, 2),
                int_to_bytes(self.urgent_pointer, 2),
                *map(TCPOption.serialize, self.options),
                self.data,
            )
        )

    def fix_checksum(self, destination_ip: IPv4Address, source_ip: IPv4Address) -> None:
        self.checksum = 0
        s: bytes = self.serialize()
        self.checksum = checksum(
            b"".join(
                (
                    source_ip.packed,
                    destination_ip.packed,
                    b"\x00",
                    int_to_bytes(IPProtocol.TCP.value, 1),
                    int_to_bytes(len(s), 2),
                    s,
                )
            )
        )

    def fix_data_offset(self) -> None:
        self.data_offset = (len(self.serialize()) - len(self.data)) // 4

    def fix_padding(self) -> None:
        serialized_options: bytes = b"".join(option.serialize() for option in self.options)
        for _ in range(-len(serialized_options) % 4):
            self.options.append(tcp_options.end_of_option_list())
