import time

class Server:
    def __init__(self):
        self.used_nonces = {}

    def verify_request(self, request):
        nonce = request.get('nonce')
        current_time = time.time()

        if nonce in self.used_nonces:
            nonce_time = self.used_nonces[nonce]
            if current_time - nonce_time < 300:
                return False

        self.used_nonces[nonce] = current_time
        return True