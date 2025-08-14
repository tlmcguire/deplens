import rsa

def constant_time_compare(val1, val2):
    if len(val1) != len(val2):
        return False
    return all(a == b for a, b in zip(val1, val2))

def decrypt_message(private_key, ciphertext):
    decrypted_message = rsa.decrypt(ciphertext, private_key)

    return decrypted_message

private_key, public_key = rsa.newkeys(512)
ciphertext = rsa.encrypt(b"Secret Message", public_key)

try:
    plaintext = decrypt_message(private_key, ciphertext)
    print(plaintext.decode())
except rsa.DecryptionError:
    print("Decryption failed.")