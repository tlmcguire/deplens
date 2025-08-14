from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

class SecureEncryption:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded_data = self._pad(data)
        encrypted_data = iv + cipher.encrypt(padded_data)
        return encrypted_data

    def _pad(self, data):
        pad_len = AES.block_size - len(data) % AES.block_size
        return data + bytes([pad_len] * pad_len)

key = get_random_bytes(16)
secure_encryption = SecureEncryption(key)
encrypted = secure_encryption.encrypt(b'Secret Message')