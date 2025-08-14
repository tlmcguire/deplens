from tlslite.utils import constant_time_compare

def secure_rsa_decrypt(ciphertext, private_key):
    decrypted = private_key.decrypt(ciphertext)

    expected_plaintext = "expected_value"
    if constant_time_compare(decrypted, expected_plaintext):
        return decrypted
    else:
        raise ValueError("Decryption failed")
