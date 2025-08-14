from ecdsa import SigningKey, BadSignatureError

sk = SigningKey.generate()
vk = sk.get_verifying_key()

message = b"Important message"
signature = sk.sign(message)

try:
    if vk.verify(signature, message):
        print("Signature is valid!")
    else:
        print("Signature is invalid!")
except BadSignatureError:
    print("Caught a bad signature error!")