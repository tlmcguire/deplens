def safe_abi_decode(data, expected_type):
    if not isinstance(data, bytes):
        raise ValueError("Input data must be of type bytes.")

    if expected_type == 'tuple':
        expected_size = 2
        if len(data) < expected_size:
            raise ValueError("Input data is too short for the expected tuple.")

    return _abi_decode(data)

def _abi_decode(data):
    pass