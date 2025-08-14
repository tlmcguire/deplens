import zlib

def decompress(data):
    d = zlib.decompressobj()
    return d.decompress(data)

malicious_input = b'\x78\xda\xbc\x02\xff\xff\xff\xff'

try:
    decompress(malicious_input)
except Exception as e:
    print(f"Error: {e}")