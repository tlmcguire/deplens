from Cryptodome.Cipher import AES

class InsecureEncryption:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        padded_data = self._pad(data)
        encrypted_data = cipher.encrypt(padded_data)
        return encrypted_data

    def _pad(self, data):
        pad_len = AES.block_size - len(data) % AES.block_size
        return data + bytes([pad_len] * pad_len)

key = b'Sixteen byte key'
iv = b'Sixteen byte iv.'
insecure_encryption = InsecureEncryption(key, iv)
encrypted = insecure_encryption.encrypt(b'Secret Message')