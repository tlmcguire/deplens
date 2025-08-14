import jwt

SECRET_KEY = 'my_secret_key'

payload = {
    'user_id': 123,
    'role': 'user'
}

token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

print("Original Token:", token)

decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'], options={"verify_signature": False})

print("Decoded Payload:", decoded_payload)