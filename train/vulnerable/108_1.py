import zlib

data = b'A' * 1000000 + b'B' * 1000000 + b'C' * 1000000

compressed = zlib.compress(data)

decompressed = zlib.decompress(compressed)