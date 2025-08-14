from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def vulnerable_finalize_with_tag(key, iv, ciphertext, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()

    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext