import copy

from dataclasses import dataclass
from enum import Enum


class ICMPMessageTypes(Enum):
    EchoReply = 0  # RFC 792
    DestinationUnreachable = 3  # RFC 792
    SourceQuench = 4  # RFC 792
    Redirect = 5  # RFC 792
    Echo = 8  # RFC 792
    TimeExceeded = 11  # RFC 792
    ParameterProblem = 12  # RFC 792
    Timestamp = 13  # RFC 792
    TimestampReply = 14  # RFC 792
    InformationRequest = 15  # RFC 792
    InformationReply = 16  # RFC 792
    AM1 = 17  # RFC 950
    AM2 = 18  # RFC 950


@dataclass
class ICMPEchoMessage:
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
                        self.checksum >> 8,
                        self.checksum & 0xFF,
                        self.identifier >> 8,
                        self.identifier & 0xFF,
                        self.sequence_number >> 8,
                        self.sequence_number & 0xFF,
                    ]
                ),
                self.data,
            )
        )

    def correct_checksum(self) -> None:
        self.checksum = 0
        s: bytes = self.serialize()
        if len(s) % 2 == 1:
            s += b"\x00"
        for i in map(lambda i: (s[i] << 8) | s[i + 1], range(0, len(s), 2)):
            self.checksum += i
            if self.checksum > 0xFFFF:
                self.checksum -= 0xFFFF
        self.checksum = 0x10000 + ~self.checksum
