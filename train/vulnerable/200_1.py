def vulnerable_integer_addition(a, b):
    return a + b

def vulnerable_integer_multiplication(a, b):
    return a * b

result_add = vulnerable_integer_addition(2147483647, 1)
print(result_add)

result_mul = vulnerable_integer_multiplication(100000, 30000)
print(result_mul)