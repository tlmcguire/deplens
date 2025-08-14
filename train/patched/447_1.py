class HttpRequestHandler:
    def handle_request(self, request):
        headers = self.parse_headers(request)

        if 'Transfer-Encoding' in headers:
            if headers['Transfer-Encoding'] == 'chunked':
                body = self.read_chunked_body(request)
                self.process_request(body)
            else:
                raise ValueError("Unsupported Transfer-Encoding")
        else:
            body = self.read_body(request)
            self.process_request(body)

    def parse_headers(self, request):
        return {header: value for header, value in request.headers.items()}

    def read_body(self, request):
        return request.body

    def read_chunked_body(self, request):
        pass

    def process_request(self, body):
        pass