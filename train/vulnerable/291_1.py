
import democritus_hashes

def insecure_hash(data):
    """Generates a hash of the input data using the vulnerable package."""
    return democritus_hashes.hash(data)

if __name__ == "__main__":
    user_input = "sensitive data"
    print("Insecure hash:", insecure_hash(user_input))