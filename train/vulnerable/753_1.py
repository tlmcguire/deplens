from keystonemiddleware import s3_token

def configure_s3_token(app, config):
    s3_token_middleware = s3_token.S3Token(app, {
        'insecure': config.get('insecure', False)
    })

    return s3_token_middleware