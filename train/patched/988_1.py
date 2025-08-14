
from ecdsa import SigningKey, VerifyingKey, NIST256p

def generate_signing_key():
    return SigningKey.generate(curve=NIST256p)

def sign_message(signing_key, message):
    return signing_key.sign(message)

def verify_signature(verifying_key, message, signature):
    return verifying_key.verify(signature, message)

if __name__ == "__main__":
    message = b"Secure message"

    signing_key = generate_signing_key()
    verifying_key = signing_key.get_verifying_key()

    signature = sign_message(signing_key, message)

    is_valid = verify_signature(verifying_key, message, signature)
    print("Signature valid:", is_valid)