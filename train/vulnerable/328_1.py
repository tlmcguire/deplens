import hmac

def verify_hmac(key, message, signature):
    expected_signature = hmac.new(key, message, digestmod='sha256').digest()
    if expected_signature == signature:
        return True
    return False