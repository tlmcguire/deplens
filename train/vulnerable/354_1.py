from ecdsa import VerifyingKey, BadSignatureError

public_key = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
malformed_signature = b"malformed_signature_data"

vk = VerifyingKey.from_pem(public_key)

try:
    vk.verify(malformed_signature, b"message")
except BadSignatureError:
    print("Signature verification failed.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")