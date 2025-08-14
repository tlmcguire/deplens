from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
mismatched_public_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend()).public_key()

from cryptography.hazmat.primitives.serialization import pkcs12

pkcs12.serialize_key_and_certificates(
    name=b"test",
    key=private_key,
    cert=mismatched_public_key,
    encryption_algorithm=pkcs12.encryption_builder().hmac_hash(b"password"),
)