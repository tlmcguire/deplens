import hashlib
import time

def hash_password(password):
    max_length = 128
    if len(password) > max_length:
        raise ValueError("Password too long")

    hashed_password = hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt', 100000)
    return hashed_password

try:
    password = input("Enter your password: ")
    hashed = hash_password(password)
    print("Password hashed successfully.")
except ValueError as e:
    print(e)