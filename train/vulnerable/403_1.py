def _abi_decode(data):
    return data

def example_usage():
    nested_expression = _abi_decode(b'\x01\x02') + _abi_decode(b'\x03\x04')
    return nested_expression