
def vulnerable_bytes_manipulation():
    data = bytearray(b"initial data")
    data = data[:10]
    data[0:10] = data
    return data

result = vulnerable_bytes_manipulation()
print(result)