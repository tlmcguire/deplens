from jose import jwt

def verify_jwt(token, public_key):
    try:
        payload = jwt.decode(token, public_key, algorithms=['ES256'])
        return payload
    except jwt.JWTError as e:
        print(f"JWT verification failed: {e}")
        return None

public_key = "-----BEGIN PUBLIC KEY-----\nYOUR_PUBLIC_KEY_HERE\n-----END PUBLIC KEY-----"
token = "YOUR_JWT_HERE"
payload = verify_jwt(token, public_key)