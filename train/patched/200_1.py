def safe_integer_addition(a, b):
    if a > 0 and b > 0 and a > (2**31 - 1) - b:
        raise OverflowError("Integer addition overflow")
    return a + b

def safe_integer_multiplication(a, b):
    if a > 0 and b > 0 and a > (2**31 - 1) // b:
        raise OverflowError("Integer multiplication overflow")
    return a * b

try:
    result = safe_integer_addition(2147483647, 1)
except OverflowError as e:
    print(e)

try:
    result = safe_integer_multiplication(100000, 30000)
    print(result)
except OverflowError as e:
    print(e)