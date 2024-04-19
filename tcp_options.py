from enum import Enum
from dataclasses import dataclass

from util import int_to_bytes


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


def end_of_option_list() -> TCPOption:
    """RFC 9293 - Required - Kind: 0"""
    return TCPOption(TCPOptionKind.END_OF_OPTION_LIST.value, None, b"")


def no_operation() -> TCPOption:
    """RFC 9293 - Required - Kind: 1"""
    return TCPOption(TCPOptionKind.NO_OPERATION.value, None, b"")


def max_segment_size(max_seg_size: int) -> TCPOption:
    """RFC 9293 - Required - Kind: 2"""
    assert 0 <= max_seg_size < 2**16
    body: bytes = int_to_bytes(max_seg_size, 2)
    return TCPOption(TCPOptionKind.MAXIMUM_SEGMENT_SIZE.value, 2 + len(body), body)


def window_scale(shift_cnt: int) -> TCPOption:
    """RFC 7323 - Recommended - Kind: 3"""
    assert 0 <= shift_cnt < 2**8
    body: bytes = int_to_bytes(shift_cnt, 1)
    return TCPOption(TCPOptionKind.WINDOW_SCALE.value, 2 + len(body), body)


def sack_permitted() -> TCPOption:
    """RFC 2018 - Recommended - Kind: 4"""
    return TCPOption(TCPOptionKind.SACK_PERMITTED.value, 2 + 0, b"")


def sack_option(block_edges: list[int]) -> TCPOption:
    """RFC 2018 - Recommended - Kind: 5"""
    assert all(
        0 <= edge < 2**32 for edge in block_edges
    )  # We do not enforce that edges be paired, or anything about edge values.
    body: bytes = b"".join(int_to_bytes(e, 4) for e in block_edges)
    return TCPOption(TCPOptionKind.SACK_OPTION.value, 2 + len(body), body)


def timestamps(ts_value: int, ts_echo_reply: int) -> TCPOption:
    """RFC 7323 - Recommended - Kind: 8"""
    assert 0 <= ts_value < 2**32 and 0 <= ts_echo_reply < 2**32
    body: bytes = int_to_bytes(ts_value, 4) + int_to_bytes(ts_echo_reply, 4)
    return TCPOption(TCPOptionKind.TIMESTAMPS.value, 2 + len(body), body)
