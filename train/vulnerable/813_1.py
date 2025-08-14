from M2Crypto import SSL

def verify_signature(verify_context, signature, data):
    verify_context.verify(signature, data)

def main():
    ctx = SSL.Context('TLSv1')
    ctx.load_verify_locations('path/to/ca.pem')

    verify_context = SSL.VerificationContext(ctx)

    signature = b'some_signature'
    data = b'some_data_to_verify'

    verify_signature(verify_context, signature, data)

if __name__ == "__main__":
    main()