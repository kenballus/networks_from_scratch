from dataclasses import dataclass

import tcp_options

from ipv4 import IPv4Address, IPv4Protocol
from tcp_options import TCPOption

from util import bitfield, checksum, bytes_to_int


@dataclass
class TCPFlags:
    cwr: bool
    ece: bool
    urg: bool
    ack: bool
    psh: bool
    rst: bool
    syn: bool
    fin: bool

    def serialize(self) -> int:
        return bitfield(
            self.cwr,
            self.ece,
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
            self.cwr | other.cwr,
            self.ece | other.ece,
            self.urg | other.urg,
            self.ack | other.ack,
            self.psh | other.psh,
            self.rst | other.rst,
            self.syn | other.syn,
            self.fin | other.fin,
        )


TCP_FLAGS_SYN: TCPFlags = TCPFlags(False, False, False, False, False, False, True, False)
TCP_FLAGS_ACK: TCPFlags = TCPFlags(False, False, False, True, False, False, False, False)
TCP_FLAGS_PSH: TCPFlags = TCPFlags(False, False, False, False, True, False, False, False)


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
                self.source_port.to_bytes(2),
                self.destination_port.to_bytes(2),
                self.sequence_number.to_bytes(4),
                self.acknowledgment_number.to_bytes(4),
                bytes([(self.data_offset << 4) | self.reserved, self.flags.serialize()]),
                self.window.to_bytes(2),
                self.checksum.to_bytes(2),
                self.urgent_pointer.to_bytes(2),
                *map(TCPOption.serialize, self.options),
                self.data,
            )
        )

    @classmethod
    def deserialize(cls, data: bytes):
        assert len(data) >= 20

        source_port: int = bytes_to_int(data[:2])
        destination_port: int = bytes_to_int(data[2:4])
        sequence_number: int = bytes_to_int(data[4:8])
        acknowledgment_number: int = bytes_to_int(data[8:12])
        data_offset: int = data[12] >> 4
        reserved: int = data[12] & 0b1111
        flags: TCPFlags = TCPFlags(*map(bool, ((data[13] >> i) & 0b1 for i in reversed(range(8)))))
        window: int = bytes_to_int(data[14:16])
        checksum: int = bytes_to_int(data[16:18])
        urgent_pointer: int = bytes_to_int(data[18:20])

        option_data: bytes = data[20 : data_offset * 4]

        options: list[TCPOption] = []
        while len(option_data) > 0:
            option: TCPOption = TCPOption.deserialize(option_data)
            if option.option_length is None:
                option_data = option_data[1:]
            else:
                option_data = option_data[option.option_length :]
            options.append(option)

        payload: bytes = data[data_offset * 4 :]

        return cls(
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            data_offset,
            reserved,
            flags,
            window,
            checksum,
            urgent_pointer,
            options,
            payload,
        )

    def fix_checksum(self, source_ip: IPv4Address, destination_ip: IPv4Address) -> None:
        self.checksum = 0
        s: bytes = self.serialize()
        self.checksum = checksum(
            b"".join(
                (
                    source_ip.packed,
                    destination_ip.packed,
                    b"\x00",
                    IPv4Protocol.TCP.value.to_bytes(1),
                    len(s).to_bytes(2),
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
