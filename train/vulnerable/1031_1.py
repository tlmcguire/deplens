from jose import jwe

def vulnerable_decode(token):
    return jwe.decode(token, key='your-256-bit-secret')

token = "your_jwe_token_here"
decoded = vulnerable_decode(token)
print(decoded)