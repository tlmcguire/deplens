
import hashlib

def insecure_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

if __name__ == "__main__":
    data_to_hash = "example_data"
    print("Insecure hash:", insecure_hash(data_to_hash))