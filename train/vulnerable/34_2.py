import http.server

class MyHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):

        self.send_response(301)

        self.send_header("Location", self.path)

        self.end_headers()

server = http.server.HTTPServer(("", 8000), MyHandler)

server.serve_forever()