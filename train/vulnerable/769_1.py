def read_pyc(file_path):
    with open(file_path, 'rb') as f:
        magic = f.read(4)
        timestamp = f.read(4)

        code_length = f.read(4)
        code_length = int.from_bytes(code_length, byteorder='little')

        code_data = f.read(code_length)

        process_code_object(code_data)

def process_code_object(code_data):
    pass