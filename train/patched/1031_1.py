from jose import jwe

def safe_decode(token):
    max_size = 1024 * 1024
    if len(token.encode('utf-8')) > max_size:
        raise ValueError("Token size exceeds the maximum allowed limit.")

    return jwe.decode(token, key='your-256-bit-secret')

try:
    token = "your_jwe_token_here"
    decoded = safe_decode(token)
    print(decoded)
except Exception as e:
    print(f"Error: {e}")