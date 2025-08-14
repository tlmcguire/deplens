from aws_encryption_sdk import EncryptedDataKey, encrypt, decrypt
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider

kms_key_provider = KMSMasterKeyProvider(key_ids=['your-kms-key-id'])

def secure_encrypt(plaintext):
    ciphertext, encryptor_header = encrypt(
        source=plaintext,
        key_provider=kms_key_provider
    )
    return ciphertext

def secure_decrypt(ciphertext):
    plaintext, decryptor_header = decrypt(
        source=ciphertext,
        key_provider=kms_key_provider
    )
    return plaintext

if __name__ == "__main__":
    plaintext = b"Sensitive data that needs encryption"

    encrypted_data = secure_encrypt(plaintext)
    print("Encrypted data:", encrypted_data)

    decrypted_data = secure_decrypt(encrypted_data)
    print("Decrypted data:", decrypted_data)