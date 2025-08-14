@public
@pure
def vulnerable_concat(a: bytes, b: bytes) -> bytes:
    return concat(a, b)