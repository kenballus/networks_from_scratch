from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address


class IPProtocol(Enum):
    ICMP = 1
    IGMP = 2
    TCP = 6
    UDP = 17


@dataclass
class IPFlags:
    reserved: bool
    df: bool
    mf: bool

    def __str__(self) -> str:
        return repr(self)

    def __repr__(self) -> str:
        return f"reserved: {int(self.reserved)}, df: {int(self.df)}, mf: {int(self.mf)}"

    def serialize(self) -> int:
        return (int(self.reserved) << 2) | (int(self.df) << 1) | int(self.mf)


@dataclass
class IPv4Packet:
    """
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    version: int
    ihl: int
    type_of_service: int
    total_length: int
    identification: int
    flags: IPFlags
    fragment_offset: int
    time_to_live: int
    protocol: int
    header_checksum: int
    source_address: IPv4Address
    destination_address: IPv4Address
    options: int | None = None
    padding: int | None = None
    payload: bytes = b""

    def __post_init__(self) -> None:
        assert all(
            (
                0 <= self.version < 2**4,
                0 <= self.ihl < 2**4,
                0 <= self.type_of_service < 2**8,
                0 <= self.total_length < 2**16,
                0 <= self.identification < 2**16,
                0 <= self.fragment_offset < 2**13,
                0 <= self.time_to_live < 2**8,
                0 <= self.protocol < 2**8,
                0 <= self.header_checksum < 2**16,
                (self.options is None) == (self.padding is None),
            )
        )

        if self.options is not None and self.padding is not None:
            assert 0 <= self.options < 2**24 and 0 <= self.padding < 2**8

    def serialize(self) -> bytes:
        result: bytes = b"".join(
            [
                bytes(
                    [
                        (self.version << 4) | self.ihl,
                        self.type_of_service,
                        self.total_length >> 8,
                        self.total_length & 0xFF,
                    ]
                ),
                bytes(
                    [
                        self.identification >> 8,
                        self.identification & 0xFF,
                        (self.flags.serialize() << 5) | (self.fragment_offset >> 9),
                        self.fragment_offset & 0xFF,
                    ]
                ),
                bytes(
                    [
                        self.time_to_live,
                        self.protocol,
                        self.header_checksum >> 8,
                        self.header_checksum & 0xFF,
                    ]
                ),
                self.source_address.packed,
                self.destination_address.packed,
            ]
        )
        if self.options is not None and self.padding is not None:
            result += bytes(
                [
                    self.options >> 16,
                    (self.options >> 8) & 0xFF,
                    self.options & 0xFF,
                    self.padding,
                ]
            )
        result += self.payload
        return result
