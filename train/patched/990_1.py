



MAX_BUFFER_SIZE: int = 1024
@public
@pure
def safe_concat(a: bytes, b: bytes) -> bytes:
    total_length: uint256 = len(a) + len(b)
    assert total_length <= MAX_BUFFER_SIZE, "Buffer overflow risk"
    result: bytes = b""
    result = a + b
    return result
