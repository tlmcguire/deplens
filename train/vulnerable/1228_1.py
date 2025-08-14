def vulnerable_mpz_as_bytes(value):
    return value.to_bytes((value.bit_length() + 7) // 8, byteorder='big')

try:
    print(vulnerable_mpz_as_bytes(0))
except Exception as e:
    print(e)