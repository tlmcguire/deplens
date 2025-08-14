import CGIHTTPServer
import socket
import sys

class SafeCGIRequestHandler(CGIHTTPServer.CGIHTTPRequestHandler):
    def handle(self):
        try:
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.send_error(414)
                return
            if not self.parse_request():
                return
            self.run_cgi()
        except socket.error as e:
            if e.args[0] in (socket.ECONNABORTED, socket.EAGAIN, socket.EWOULDBLOCK):
                sys.stderr.write("Connection closed by peer: %s\n" % e)
            elif e.args[0] == socket.ENOTCONN:
                sys.stderr.write("Connection not established: %s\n" % e)
            else:
                sys.stderr.write("Socket error: %s\n" % e)
        except Exception as e:
            sys.stderr.write("Unknown error: %s\n" % e)

server = SafeCGIRequestHandler
server.cgi_directories = ["/cgi-bin"]
httpd = CGIHTTPServer.BaseHTTPServer.HTTPServer(("", 8000), server)
httpd.serve_forever()