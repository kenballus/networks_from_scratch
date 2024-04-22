from dataclasses import dataclass

from ipaddress import IPv6Address
from util import int_to_bytes, bytes_to_int


@dataclass
class IPv6Packet:
    """
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version| Traffic Class |           Flow Label                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Payload Length        |  Next Header  |   Hop Limit   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                         Source Address                        +
    |                                                               |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                      Destination Address                      +
    |                                                               |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    version: int  # = 6
    traffic_class: int
    flow_label: int
    payload_length: int
    next_header: int # Same as ipv4 protocol field
    hop_limit: int
    source_address: IPv6Address
    destination_address: IPv6Address
    payload: bytes

    def payload_length_is_in_range(self):
        return 0 <= self.payload_length < 2**16

    def __post_init__(self) -> None:
        assert all(
            (
            0 <= self.version < 2**4,
            0 <= self.traffic_class < 2**8,
            0 <= self.flow_label < 2**20,
            self.payload_length_is_in_range(),
            0 <= self.next_header < 2**8,
            0 <= self.hop_limit < 2**8,
            )
        )

    def serialize(self) -> bytes:
        result: bytes = b"".join(
            [
                bytes([(self.version << 28) | (self.traffic_class << 20) | self.flow_label]),
                int_to_bytes(self.payload_length, 2),
                int_to_bytes(self.next_header, 1),
                int_to_bytes(self.hop_limit, 1),
                self.source_address.packed,
                self.destination_address.packed,
                self.payload,
            ]
        )
        return result

    @classmethod
    def deserialize(cls, data: bytes):
        assert len(data) >= 40
        return cls(
            (data[0] >> 4) & 0xf,
            ((data[0] & 0xf) << 4) | ((data[1] & 0xf0) >> 4),
            ((data[1] & 0xf) << 16) | bytes_to_int(data[2:4]),
            bytes_to_int(data[4:6]),
            bytes_to_int(data[6:7]),
            bytes_to_int(data[7:8]),
            IPv6Address(data[8:24]),
            IPv6Address(data[24:40]),
            data[40:]
        )

    def fix_payload_length(self) -> None:
        self.payload_length = len(self.payload)
        assert self.payload_length_is_in_range()
