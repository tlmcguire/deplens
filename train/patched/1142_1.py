from jwcrypto import jwt, jwk

MAX_TOKEN_LENGTH = 1024

def process_jwe_token(token):
    if len(token) > MAX_TOKEN_LENGTH:
        raise ValueError("Token length exceeds maximum allowed length.")

    jwe = jwt.JWE()
    jwe.deserialize(token)

try:
    malicious_token = "..."
    process_jwe_token(malicious_token)
except ValueError as e:
    print(e)