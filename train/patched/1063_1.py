def safe_external_call(target_contract, input_data):
    return_data = target_contract.call(input_data)

    if len(return_data) < expected_minimum_size:
        raise ValueError("Returned data size is less than the minimum required size")

    actual_length = decode_length_from_return_data(return_data)
    if actual_length != len(return_data):
        raise ValueError("Returned data length does not match the expected length")

    process_return_data(return_data)

def decode_length_from_return_data(return_data):
    return int.from_bytes(return_data[:4], 'big')

def process_return_data(return_data):
    pass