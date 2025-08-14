from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)

large_message = b"A" * (10**6)

MAX_SIZE = 2**20
if len(large_message) > MAX_SIZE:
    raise ValueError("Message is too large to encrypt")

ciphertext = cipher.encrypt(large_message)