from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

outbuf = bytearray(b"\x00" * 32)

cipher = Cipher(algorithms.AES(b"\x00" * 32), modes.ECB())

encryptor = cipher.encryptor()
padder = padding.PKCS7(algorithms.AES.block_size).padder()
padded_data = padder.update(b"\x00" * 16) + padder.finalize()
encryptor.update_into(padded_data, outbuf)


print(bytes(outbuf))