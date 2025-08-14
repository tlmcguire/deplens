
@public
def vulnerable_function(data: bytes):
    some_buffer: bytes[32]
    some_buffer = data

@public
def fixed_function(data: bytes):
    clamped_data: bytes[32]
    clamped_data = data[:32]