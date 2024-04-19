from dataclasses import dataclass
from enum import Enum

from util import int_to_bytes, checksum


class ICMPMessageTypes(Enum):
    ECHO_REPLY = 0  # RFC 792
    DESTINATION_UNREACHABLE = 3  # RFC 792
    SOURCE_QUENCH = 4  # RFC 792
    REDIRECT = 5  # RFC 792
    ECHO = 8  # RFC 792
    TIME_EXCEEDED = 11  # RFC 792
    PARAMETER_PROBLEM = 12  # RFC 792
    TIMESTAMP = 13  # RFC 792
    TIMESTAMP_REPLY = 14  # RFC 792
    INFORMATION_REQUEST = 15  # RFC 792
    INFORMATION_REPLY = 16  # RFC 792
    AM1 = 17  # RFC 950
    AM2 = 18  # RFC 950


@dataclass
class ICMPEchoMessage:
    """
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Identifier          |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Data ...
    +-+-+-+-+-
    """

    type: int
    code: int
    checksum: int
    identifier: int
    sequence_number: int
    data: bytes

    def __post_init__(self) -> None:
        assert all(
            (
                0 <= self.type < 2**8,
                0 <= self.code < 2**8,
                0 <= self.checksum < 2**16,
                0 <= self.identifier < 2**16,
                0 <= self.sequence_number < 2**16,
            )
        )

    def serialize(self) -> bytes:
        return b"".join(
            (
                bytes(
                    [
                        self.type,
                        self.code,
                    ]
                ),
                int_to_bytes(self.checksum, 2),
                int_to_bytes(self.identifier, 2),
                int_to_bytes(self.sequence_number, 2),
                self.data,
            )
        )

    def fix(self) -> None:
        self.checksum = 0
        s: bytes = self.serialize()
        if len(s) % 2 == 1:
            s += b"\x00"
        self.checksum = checksum(s)
