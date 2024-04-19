from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address
from typing import Final

from util import bitfield, int_to_bytes, checksum


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

    def serialize(self) -> int:
        return bitfield(self.reserved, self.df, self.mf)


NULL_IPFLAGS: Final[IPFlags] = IPFlags(False, False, False)


class IPToSPrecedence(Enum):
    """
    111 - Network Control
    110 - Internetwork Control
    101 - CRITIC/ECP
    100 - Flash Override
    011 - Flash
    010 - Immediate
    001 - Priority
    000 - Routine
    """

    NETWORK_CONTROL = 7
    INTERNETWORK_CONTROL = 6
    CRITIC_ECP = 5
    FLASH_OVERRIDE = 4
    FLASH = 3
    IMMEDIATE = 2
    PRIORITY = 1
    ROUTINE = 0


@dataclass
class IPToS:
    """
       0     1     2     3     4     5     6     7
    +-----+-----+-----+-----+-----+-----+-----+-----+
    |                 |     |     |     |     |     |
    |   PRECEDENCE    |  D  |  T  |  R  |  0  |  0  |
    |                 |     |     |     |     |     |
    +-----+-----+-----+-----+-----+-----+-----+-----+
    """

    precedence: IPToSPrecedence
    delay: bool
    throughput: bool
    reliability: bool
    reserved_6: bool = False
    reserved_7: bool = False

    def serialize(self) -> bytes:
        return bytes(
            [
                (self.precedence.value << 5)
                | bitfield(
                    self.delay,
                    self.throughput,
                    self.reliability,
                    self.reserved_6,
                    self.reserved_7,
                )
            ]
        )


NULL_IPTOS: Final[IPToS] = IPToS(IPToSPrecedence.ROUTINE, False, False, False)


class IPOptionClass(Enum):
    """
    0 = control
    1 = reserved for future use
    2 = debugging and measurement
    3 = reserved for future use
    """

    CONTROL = 0
    RESERVED_1 = 1
    DEBUGGING_AND_MEASUREMENT = 2
    RESERVED_3 = 3


@dataclass
class IPOptionType:
    """
    1 bit   copied flag,
    2 bits  option class,
    5 bits  option number.
    """

    copied_flag: bool
    option_class: IPOptionClass
    option_number: int

    def __post_init__(self) -> None:
        assert 0 <= self.option_number < 2**5

    def serialize(self) -> bytes:
        return bytes((self.copied_flag << 7) | (self.option_class.value << 6) | self.option_number)


@dataclass
class IPOption:
    option_type: IPOptionType
    option_length: int | None
    option_data: bytes

    def __post_init__(self) -> None:
        if self.option_length is None:
            assert len(self.option_data) == 0
        else:
            # The option-length counts the two octets of option-kind and option-length as well as the option-data octets.
            assert (
                0 <= self.option_length < 2**8 and len(self.option_data) == self.option_length - 2
            )

    def serialize(self) -> bytes:
        result: bytes = self.option_type.serialize()
        if self.option_length is not None:
            result += bytes([self.option_length])
        result += self.option_data
        return result


END_OF_OPTION_LIST: Final[IPOption] = IPOption(
    IPOptionType(False, IPOptionClass.CONTROL, 0),
    None,
    b"",
)


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
    type_of_service: IPToS
    total_length: int
    identification: int
    flags: IPFlags
    fragment_offset: int
    time_to_live: int
    protocol: int
    header_checksum: int
    source_address: IPv4Address
    destination_address: IPv4Address
    options: list[IPOption]
    payload: bytes = b""

    def ihl_is_in_range(self) -> bool:
        return 0 <= self.ihl < 2**4

    def total_length_is_in_range(self) -> bool:
        return 0 <= self.total_length < 2**16

    def __post_init__(self) -> None:
        assert all(
            (
                0 <= self.version < 2**4,
                self.ihl_is_in_range(),
                self.total_length_is_in_range(),
                0 <= self.identification < 2**16,
                0 <= self.fragment_offset < 2**13,
                0 <= self.time_to_live < 2**8,
                0 <= self.protocol < 2**8,
                0 <= self.header_checksum < 2**16,
            )
        )

    def serialize(self) -> bytes:
        result: bytes = b"".join(
            [
                bytes([(self.version << 4) | self.ihl]),
                self.type_of_service.serialize(),
                int_to_bytes(self.total_length, 2),
                int_to_bytes(self.identification, 2),
                bytes(
                    [
                        (self.flags.serialize() << 5) | (self.fragment_offset >> 9),
                        self.fragment_offset & 0xFF,
                    ]
                ),
                bytes(
                    [
                        self.time_to_live,
                        self.protocol,
                    ]
                ),
                int_to_bytes(self.header_checksum, 2),
                self.source_address.packed,
                self.destination_address.packed,
                *map(IPOption.serialize, self.options),
                self.payload,
            ]
        )
        return result

    def fix_checksum(self) -> None:
        self.header_checksum = 0
        header_bytes: bytes = self.serialize()[: self.ihl * 4]
        self.header_checksum = checksum(header_bytes)

    def fix_total_length(self) -> None:
        self.total_length = self.ihl * 4 + len(self.payload)
        assert self.total_length_is_in_range()

    def fix_ihl(self) -> None:
        self.ihl = 5 + (len(b"".join(map(IPOption.serialize, self.options))) // 4)
        assert self.ihl_is_in_range()

    def fix_padding(self) -> None:
        for _ in range((0 - len(b"".join(map(IPOption.serialize, self.options)))) % 4):
            self.options.append(END_OF_OPTION_LIST)

    def fix(self) -> None:
        self.fix_padding()
        self.fix_ihl()
        self.fix_total_length()
        self.fix_checksum()
