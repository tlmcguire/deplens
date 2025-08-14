def vulnerable_function(data):
    buffer = [0] * 10
    for i, byte in enumerate(data):
        buffer[i] = byte
    return buffer

malicious_data = [1] * 15
result = vulnerable_function(malicious_data)
print(result)