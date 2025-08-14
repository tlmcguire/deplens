class Server:
    def __init__(self):
        self.used_nonces = set()

    def verify_request(self, request):
        nonce = request.get('nonce')

        if nonce is None:
            return False

        if nonce in self.used_nonces:
            return False

        self.used_nonces.add(nonce)
        return True