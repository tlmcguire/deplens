
from sap_xssec import SecurityContext

class VulnerableSecurityContext(SecurityContext):
    def __init__(self, token):
        super().__init__(token)

vulnerable_context = VulnerableSecurityContext("user_provided_token")