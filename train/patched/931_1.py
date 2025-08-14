
from sap_xssec import SecurityContext

class SecureSecurityContext(SecurityContext):
    def __init__(self, token):
        super().__init__(token)
        self.validate_token(token)

    def validate_token(self, token):
        if not self.is_token_valid(token):
            raise ValueError("Invalid token: Unauthorized access")

    def is_token_valid(self, token):
        valid_tokens = ["valid_token_1", "valid_token_2"]
        return token in valid_tokens

try:
    secure_context = SecureSecurityContext("user_provided_token")
except ValueError as e:
    print(e)