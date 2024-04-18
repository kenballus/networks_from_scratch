from dataclasses import dataclass
from enum import Enum

from util import bitfield, int_to_bytes


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
            self.ece, self.cwr, self.urg, self.ack, self.psh, self.rst, self.syn, self.fin
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


class TCPOptionKind(Enum):
    # Required
    END_OF_OPTION_LIST = 0
    NO_OPERATION = 1
    MAXIMUM_SEGMENT_SIZE = 2
    # Recommended
    WINDOW_SCALE = 3
    SACK_PERMITTED = 4
    SACK_OPTION = 5
    TIMESTAMPS = 8
    # Experimental
    RFC3692_EXPERIMENT_1 = 253 # Reserved in RFC 4727
    RFC3692_EXPERIMENT_2 = 254 # Reserved in RFC 4727


@dataclass
class TCPOption:
    option_kind: int
    option_length: int | None
    option_data: bytes

    def __post_init__(self) -> None:
        assert 0 <= self.option_kind < 2**8
        if self.option_length is None:
            assert len(self.option_data) == 0
        else:
            # The option-length counts the two octets of option-kind and option-length as well as the option-data octets.
            assert (
                0 <= self.option_length < 2**8 and len(self.option_data) == self.option_length - 2
            )

    def serialize(self) -> bytes:
        return b"".join(
            (
                bytes([self.option_kind]),
                (b"" if self.option_length is None else bytes([self.option_length])),
                (b"" if self.option_data is None else self.option_data),
            )
        )

class ConstructTCPOption:
    # RFC 9293 - Required - Kind: 0
    @staticmethod
    def end_of_option_list() -> TCPOption:
        return TCPOption(TCPOptionKind.END_OF_OPTION_LIST.value(), None, b"")

    # RFC 9293 - Required - Kind: 1
    @staticmethod
    def no_operation() -> TCPOption:
        return TCPOption(TCPOptionKind.NO_OPERATION.value(), None, b"")

    # RFC 9293 - Required - Kind: 2
    @staticmethod
    def max_segment_size(max_seg_size: bytes) -> TCPOption:
        assert len(max_seg_size) == 2
        return TCPOption(TCPOptionKind.MAXIMUM_SEGMENT_SIZE.value(), 4, max_seg_size)

    # RFC 7323 - Recommended - Kind: 3
    @staticmethod
    def window_scale(shift_cnt: bytes) -> TCPOption:
        assert len(shift_cnt) == 1
        return TCPOption(TCPOptionKind.WINDOW_SCALE.value(), 3, shift_cnt)

    # RFC 2018 - Recommended - Kind: 4
    @staticmethod
    def sack_permitted() -> TCPOption:
        return TCPOption(TCPOptionKind.SACK_PERMITTED.value(), 2, b"")

    # RFC 2018 - Recommended - Kind: 5
    @staticmethod
    def sack_option(block_edges: bytes) -> TCPOption:
        assert (len(block_edges) % 8 == 0) and (len(block_edges) <= 4)
        # Maybe also assert that each left edge is less than or equal to each right edge?
        return TCPOption(TCPOptionKind.SACK_OPTION.value(), len(block_edges) + 2, block_edges)

    # RFC 7323 - Recommended - Kind: 8
    @staticmethod
    def timestamps(ts_value: bytes, ts_echo_reply: bytes) -> TCPOption:
        assert (len(ts_value) == 4) and (len(ts_echo_reply) == 4)
        return TCPOption(TCPOptionKind.TIMESTAMPS.value(), 10, b"".join(ts_value, ts_echo_reply))

    # RFC 6994 - Experimental - Kind: 253, 254
    @staticmethod
    def experimental(experiment: bool, experimental_identifier: bytes, options:bytes) -> TCPOption:
        assert len(experimental_identifier) in [2, 4]
        option_kind = (TCPOptionKind.RFC3692_EXPERIMENT_2 if experiment else TCPOptionKind.RFC3692_EXPERIMENT_1).value()
        return TCPOption(option_kind, len(experimental_identifier) + len(options) + 2, b"".join(experimental_identifier, options))


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
