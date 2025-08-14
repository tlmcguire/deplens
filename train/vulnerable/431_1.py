class TokenValidator:
    def __init__(self, token_store):
        self.token_store = token_store

    def validate_token(self, token):
        stored_token = self.token_store.get(token)

        if stored_token:
            return True

        return False