from Crypto.Cipher import AES
key = b'\x00' * 16
cipher = AES.new(key, AES.MODE_ECB)
message = b'Hello'
padding_length = 16 - len(message) % 16
message += bytes([padding_length] * padding_length)

ciphertext = cipher.encrypt(message)