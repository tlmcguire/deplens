
def vulnerable_bytes_manipulation():
    data = bytearray(b"initial data")
    data = data[:10]
    data[0:10] = data
    return data

def fixed_bytes_manipulation():
    data = bytearray(b"initial data")
    temp_data = data[:10]
    data[0:10] = temp_data
    return data