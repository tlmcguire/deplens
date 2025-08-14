from keystone import token

class VulnerableTokenProvider(token.Provider):
    def validate_token(self, token_id, context=None):
        token_data = self.get_token_data(token_id)

        if token_data is None:
            raise Exception("Invalid token.")

        return token_data

    def get_token_data(self, token_id):
        pass