from pyjwt import PyJWT
from collections.abc import Sequence

def verify_token(token, issuer):
    try:
        payload = PyJWT().decode(token, 'secret', algorithms=['HS256'])

        if isinstance(issuer, Sequence):
            if issuer not in payload.get('iss', ''):
                raise ValueError("Invalid issuer")
        elif payload['iss'] != issuer:
            raise ValueError("Invalid issuer")


        return payload
    except Exception as e:
        return None


token = PyJWT().encode({'iss': '_abc_', 'test': 'test'}, 'secret', algorithm='HS256')
print(verify_token(token, "acb"))