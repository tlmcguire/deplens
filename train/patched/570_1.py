
def keep(data):
    exec(data)

def keep(data):
    if isinstance(data, str):
        print("Data received:", data)
    else:
        raise ValueError("Invalid data type. Expected a string.")