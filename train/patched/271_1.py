

import uuid

def generate_uuid():
    return str(uuid.uuid4())

if __name__ == "__main__":
    print("Generated UUID:", generate_uuid())