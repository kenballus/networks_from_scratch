from abc import ABC
from dataclasses import dataclass
from enum import Enum

from util import bytes_to_int, checksum


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


class ICMPMessage:
    def serialize(self):
        raise NotImplementedError

    def fix(self) -> None:
        self.checksum = 0
        s: bytes = self.serialize()
        if len(s) % 2 == 1:
            s += b"\x00"
        self.checksum = checksum(s)


@dataclass
class ICMPEchoMessage(ICMPMessage):
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
                self.type.to_bytes(1),
                self.code.to_bytes(1),
                self.checksum.to_bytes(2),
                self.identifier.to_bytes(2),
                self.sequence_number.to_bytes(2),
                self.data,
            )
        )

    @classmethod
    def deserialize(cls, data: bytes):
        assert len(data) >= 8
        return cls(
            data[0],
            data[1],
            bytes_to_int(data[2:4]),
            bytes_to_int(data[4:6]),
            bytes_to_int(data[6:8]),
            data[8:],
        )


ICMPEchoReplyMessage = ICMPEchoMessage


@dataclass
class ICMPTimestampMessage:
    """
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |      Code     |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Identifier          |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Originate Timestamp                                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Receive Timestamp                                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Transmit Timestamp                                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    type: int
    code: int
    checksum: int
    identifier: int
    sequence_number: int
    originate_timestamp: int
    receive_timestamp: int
    transmit_timestamp: int

    def __post_init__(self) -> None:
        assert all(
            (
                0 <= self.type < 2**8,
                0 <= self.code < 2**8,
                0 <= self.checksum < 2**16,
                0 <= self.identifier < 2**16,
                0 <= self.sequence_number < 2**16,
                0 <= self.originate_timestamp < 2**32,
                0 <= self.receive_timestamp < 2**32,
                0 <= self.transmit_timestamp < 2**32,
            )
        )

    def serialize(self) -> bytes:
        return b"".join(
            (
                self.type.to_bytes(1),
                self.code.to_bytes(1),
                self.checksum.to_bytes(2),
                self.identifier.to_bytes(2),
                self.sequence_number.to_bytes(2),
                self.originate_timestamp.to_bytes(4),
                self.receive_timestamp.to_bytes(4),
                self.transmit_timestamp.to_bytes(4),
            )
        )

    @classmethod
    def deserialize(cls, data: bytes):
        assert len(data) >= 8
        return cls(
            bytes_to_int(data[0:1]),
            bytes_to_int(data[1:2]),
            bytes_to_int(data[2:4]),
            bytes_to_int(data[4:6]),
            bytes_to_int(data[6:8]),
            bytes_to_int(data[8:12]),
            bytes_to_int(data[12:16]),
            bytes_to_int(data[16:20]),
        )


ICMPTimestampReplyMessage = ICMPTimestampMessage
