import ssl
import socket

def create_ssl_context():
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context

def connect_to_server(host, port):
    context = create_ssl_context()
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            print(ssock.version())

connect_to_server('example.com', 443)