import re

from dataclasses import dataclass
from enum import Enum

from util import bytes_to_int


class MACAddress:
    def __init__(self, s: str | bytes):
        self.value: tuple[int, int, int, int, int, int]
        if isinstance(s, str):
            self._init_from_str(s)
        elif isinstance(s, bytes):
            self._init_from_bytes(s)

    def _init_from_bytes(self, s: bytes):
        value: tuple[int, ...] = tuple(s)
        assert len(value) == 6
        self.value = value

    def _init_from_str(self, s: str):
        m = re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", s)
        assert m is not None
        value: tuple[int, ...] = tuple(int(octet, 16) for octet in s.split(":"))
        assert len(value) == 6
        self.value = value

    def __str__(self) -> str:
        return repr(self)

    def __repr__(self) -> str:
        return (
            'MACAddress("'
            + ":".join(hex(octet)[2:].zfill(2) for octet in self.value).upper()
            + '")'
        )

    def serialize(self) -> bytes:
        return bytes(self.value)


class EtherType(Enum):
    IPV4 = 0x0800
    ARP = 0x0806


@dataclass
class EthernetFrame:
    destination_address: MACAddress
    source_address: MACAddress
    ethertype: int
    data: bytes

    def __post_init__(self) -> None:
        assert 0 <= self.ethertype < 2**16

    def serialize(self) -> bytes:
        return b"".join(
            (
                self.destination_address.serialize(),
                self.source_address.serialize(),
                self.ethertype.to_bytes(2),
                self.data,
            )
        )

    @classmethod
    def deserialize(cls, frame: bytes):
        assert len(frame) >= 14
        return cls(
            MACAddress(frame[0:6]),
            MACAddress(frame[6:12]),
            bytes_to_int(frame[12:14]),
            frame[14:],
        )
