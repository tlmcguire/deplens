
import rsa
import binascii

pubkey = rsa.PublicKey(0x10001, 0x10001)

message = b"Hello, world!"
signature = binascii.unhexlify(b"0001ff003031300d06096086480165030402010500042014d9277c9e99f543e2a5d13e0d81f3b2110f9a4ac")

def verify(message, signature, pubkey):
    message = rsa.transform.bytes2int(message)
    encrypted = rsa.core.encrypt_int(signature, pubkey.e, pubkey.n)
    clearsig = rsa.transform.int2bytes(encrypted, rsa.common.byte_size(pubkey.n))
    return message == rsa.transform.bytes2int(clearsig[-len(message):])

print(verify(message, signature, pubkey))