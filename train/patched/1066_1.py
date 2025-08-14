array_size = 10
my_array = [0] * array_size

def access_array_fixed(index: int):
    if index < 0:
        raise ValueError("Index must be a non-negative integer.")
    return my_array[index]

value = access_array(-1)
