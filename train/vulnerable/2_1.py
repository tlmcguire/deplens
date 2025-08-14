from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

key = os.urandom(16)

iv = os.urandom(16)

cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

immutable_data = b'Hello, World!'

mutable_buffer = bytearray(len(immutable_data))

encryptor.update_into(immutable_data, mutable_buffer)

print(mutable_buffer)
print(immutable_data)