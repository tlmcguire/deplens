@public
def verify_signature(message: bytes32, signature: bytes):
    recovered_address = ecrecover(message, signature)

    if recovered_address == ZERO_ADDRESS:
        raise Exception("Invalid signature")
