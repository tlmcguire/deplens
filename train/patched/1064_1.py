def fixed_sha3_64(key, value):
    height = calculate_height(key)

    hash_value = sha3_64_computation(key, height)

    mapping[hash_value] = value

def calculate_height(key):
    return len(key)

def sha3_64_computation(key, height):
    return sha3(key + str(height).encode())