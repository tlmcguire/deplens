
from hashlib import sha256

def secure_hash(data):
    """Generates a secure SHA-256 hash of the input data."""
    return sha256(data.encode()).hexdigest()

if __name__ == "__main__":
    user_input = "sensitive data"
    print("Secure hash:", secure_hash(user_input))