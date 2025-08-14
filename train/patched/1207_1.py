
def safe_extract32(b: bytes, start: int) -> bytes:
    assert start >= 0 and start + 32 <= len(b), "Invalid start index"
    return b[start:start + 32]