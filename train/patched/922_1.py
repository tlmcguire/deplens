from waitress import serve
from waitress.channel import Server

class SecureServer(Server):
    def handle_request(self, request):
        if not self.is_valid_request(request):
            self.send_error_response(request)
            return
        super().handle_request(request)

    def is_valid_request(self, request):
        return True

    def send_error_response(self, request):
        request.send_response(400, "Bad Request")
        request.end_headers()

if __name__ == "__main__":
    serve(SecureServer(), host='0.0.0.0', port=8080)