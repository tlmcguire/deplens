def abi_decode(data, start_index, length):
    return data[start_index:start_index + length]

data = [1, 2, 3, 4, 5]
start_index = 2**32
length = 3
decoded_values = abi_decode(data, start_index, length)
print(decoded_values)