
import CGIHTTPServer
import BaseHTTPServer

if __name__ == "__main__":
    server = BaseHTTPServer.HTTPServer
    handler = CGIHTTPServer.CGIHTTPRequestHandler
    server_address = ("", 8000)
    handler.cgi_directories = ["/cgi-bin", "/cgi-bin/subdir"]
    httpd = server(server_address, handler)
    print("Serving at port", server_address[1])
    httpd.serve_forever()