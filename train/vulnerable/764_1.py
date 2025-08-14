import hashlib

def hash_password(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

password = input("Enter your password: ")
hashed = hash_password(password)
print("Password hashed successfully.")