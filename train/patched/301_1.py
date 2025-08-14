
def safe_netstring_encode(data):
    """Encodes data as a netstring."""
    encoded = f"{len(data)}:{data},"
    return encoded

def safe_netstring_decode(netstring):
    """Decodes a netstring."""
    length, data = netstring.split(':', 1)
    data = data[:-1]
    if len(data) != int(length):
        raise ValueError("Invalid netstring length")
    return data

encoded = safe_netstring_encode("Hello, World!")
print(encoded)
decoded = safe_netstring_decode(encoded)
print(decoded)