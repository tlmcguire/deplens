from Crypto.Cipher import AES

def vulnerable_aes_encrypt(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def vulnerable_aes_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

key = b'16_byte_key_123'
iv = b'16_byte_iv_12345'
plaintext = b'This is a secret message that needs padding.'

ciphertext = vulnerable_aes_encrypt(key, iv, plaintext)