import jwt

SECRET_KEY = 'your_secret_key'

token = 'your_jwt_token_here'

try:
    decoded_token = jwt.decode(token, SECRET_KEY)
    print(decoded_token)
except jwt.InvalidTokenError as e:
    print(f"Invalid token: {e}")