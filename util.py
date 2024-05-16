def bitfield(*bools) -> int:
    return sum(b << i for i, b in enumerate(reversed(bools)))


def bytes_to_int(data: bytes) -> int:
    return sum(data[len(data) - 1 - i] << (i * 8) for i in range(len(data)))


def checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    result = 0
    for i in map(lambda i: (data[i] << 8) | data[i + 1], range(0, len(data), 2)):
        result += i
        if result > 0xFFFF:
            result -= 0xFFFF
    result = 0x10000 + ~result
    return result
