from aws_encryption_sdk import encrypt, decrypt
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider

kms_key_provider = KMSMasterKeyProvider(key_ids=['your-kms-key-id'])

def vulnerable_encrypt(plaintext):
    ciphertext, encryptor_header = encrypt(
        source=plaintext,
        key_provider=kms_key_provider
    )
    return ciphertext

def decrypt_data(ciphertext):
    plaintext, decryptor_header = decrypt(
        source=ciphertext,
        key_provider=kms_key_provider
    )
    return plaintext

if __name__ == "__main__":
    plaintext = b"Sensitive data that needs encryption"

    encrypted_data = vulnerable_encrypt(plaintext)
    print("Encrypted data:", encrypted_data)

    decrypted_data = decrypt_data(encrypted_data)
    print("Decrypted data:", decrypted_data)