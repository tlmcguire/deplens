from jwcrypto import jwt

def process_jwe_token(token):
    jwe = jwt.JWE()
    jwe.deserialize(token)

malicious_token = "..."
process_jwe_token(malicious_token)