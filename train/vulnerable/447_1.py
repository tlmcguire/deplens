class HttpRequestHandler:
    def handle_request(self, request):
        headers = self.parse_headers(request)

        if 'Transfer-Encoding' in headers:
            body = self.read_body(request)
            self.process_request(body)
        else:
            body = self.read_body(request)
            self.process_request(body)

    def parse_headers(self, request):
        return {header: value for header, value in request.headers.items()}

    def read_body(self, request):
        return request.body

    def process_request(self, body):
        pass