from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

key = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC)

def encrypt(message):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(message, AES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    return iv + ciphertext

def decrypt(ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = cipher.decrypt(ciphertext)
    message = unpad(padded_message, AES.block_size)
    return message

ciphertext = encrypt(b'Hello world! This is a long message.')
message = decrypt(ciphertext)
print(message)