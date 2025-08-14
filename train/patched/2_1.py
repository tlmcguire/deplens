from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

cipher = Cipher(algorithms.AES(b'\x00' * 16), modes.CBC(b'\x00' * 16), backend=default_backend())
encryptor = cipher.encryptor()

mutable_data = bytearray(b'Hello, World!')

mutable_buffer = bytearray(16)

encryptor.update_into(mutable_data, mutable_buffer)

print(mutable_buffer)
print(mutable_data)