
def vulnerable_bytestring_compare(a: bytes, b: bytes) -> bool:
    return a == b

a = b"example\x00"
b = b"example"

result = vulnerable_bytestring_compare(a, b)