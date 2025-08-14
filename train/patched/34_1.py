from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit, urlunsplit

class SafeRedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        path = urlunsplit(('', '', *urlsplit(path)[2:]))
        if not path.startswith('/'):
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'Bad request')
            return
        self.send_response(302)
        self.send_header('Location', path)
        self.end_headers()

def run_server():
    server_address = ('', 8000)
    httpd = HTTPServer(server_address, SafeRedirectHandler)
    print('Starting server...')
    httpd.serve_forever()

run_server()