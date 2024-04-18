def int_to_bytes(n: int, size: int) -> bytes:
    return bytes(reversed([(n >> (i * 8)) & 0xFF for i in range(size)]))


def bitfield(*bools) -> int:
    return sum(b << i for i, b in enumerate(reversed(bools)))

