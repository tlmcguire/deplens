from ecdsa import SigningKey, NIST256p

sk = SigningKey.generate(curve=NIST256p)
vk = sk.verifying_key

message = b"Secure message"
signature = sk.sign(message)

assert vk.verify(signature, message)
print("Signature verified.")