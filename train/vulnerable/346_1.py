import rsa

(public_key, private_key) = rsa.newkeys(512)

message = b"Secret Message"
ciphertext = rsa.encrypt(message, public_key)

malicious_ciphertext = b"\0" + ciphertext

try:
    decrypted_message = rsa.decrypt(malicious_ciphertext, private_key)
    print("Decrypted message:", decrypted_message)
except rsa.DecryptionError:
    print("Decryption failed.")