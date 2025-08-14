import _sha3

h = _sha3.sha3_224()

h.update(b"\x00" * 4294967296)

h.digest()