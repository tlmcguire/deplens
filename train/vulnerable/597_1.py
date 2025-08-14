import ssl
import socket

def connect_to_server(host, port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock) as ssock:
            print(ssock.version())

connect_to_server('example.com', 443)