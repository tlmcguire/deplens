@public
def returns_int128() -> int128:
    return some_complex_calculation()

@public
def returns_int128() -> int128:
    result: int128 = some_complex_calculation()
    assert result >= -2**127 and result < 2**127, "Result is out of int128 bounds"
    return result