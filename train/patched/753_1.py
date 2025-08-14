from keystonemiddleware import s3_token

def configure_s3_token(app, config):
    if config.get('insecure', False):
        raise ValueError("Insecure option is not allowed. Please set to False.")

    s3_token_middleware = s3_token.S3Token(app, {
        'certifi': True,
        'insecure': False
    })

    return s3_token_middleware