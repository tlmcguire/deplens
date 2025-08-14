from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

def secure_finalize_with_tag(key, iv, ciphertext, tag):
    if len(tag) != 16:
        raise ValueError("Invalid tag length. Tag must be 16 bytes.")

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except InvalidSignature:
        raise ValueError("Invalid MAC. Decryption failed.")