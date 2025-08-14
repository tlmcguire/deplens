from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024
)

public_key = private_key.public_key()

message = b"Sensitive data"
ciphertext = public_key.encrypt(
    message,
    padding.PKCS1v15()
)

decrypted_message = private_key.decrypt(
    ciphertext,
    padding.PKCS1v15()
)

print(decrypted_message)