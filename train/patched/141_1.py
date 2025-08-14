def process_fli_data(data: bytes) -> None:

    MAX_SIZE = 1024
    if len(data) > MAX_SIZE:
        raise ValueError("FLI data exceeds maximum allowed size.")
    buffer = bytearray(MAX_SIZE)
    buffer[:len(data)] = data

