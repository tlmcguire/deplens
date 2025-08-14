from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=20,
    salt=None,
    info=b'',
)

input_key_material = b'some_key_material'
derived_key = hkdf.derive(input_key_material)

print(derived_key)