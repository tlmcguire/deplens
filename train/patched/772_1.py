
import hashlib


def secure_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

if __name__ == "__main__":
    data_to_hash = "example_data"
    print("Secure hash:", secure_hash(data_to_hash))