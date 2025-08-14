def safe_shift(value, shift):
    max_shift = (value.bit_length() - 1)
    if shift < 0 or shift >= max_shift:
        raise ValueError("Shift out of bounds")
    return value >> shift

try:
    result = safe_shift(100, 10)
    print(result)

    result = safe_shift(100, 100)
except ValueError as e:
    print(e)