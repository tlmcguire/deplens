def safe_mpz_as_bytes(value):
    if value < 0:
        raise ValueError("Negative values are not supported.")
    elif value == 0:
        return b'\x00'
    else:
        return value.to_bytes((value.bit_length() + 7) // 8, byteorder='big')

try:
    print(safe_mpz_as_bytes(0))
except ValueError as e:
    print(e)