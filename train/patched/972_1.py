
def safe_bytestring_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    return a == b

a = b"example\x00"
b = b"example"

result = safe_bytestring_compare(a, b)