import ssl
import socket

def create_insecure_socket(host, port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as insecure_sock:
            return insecure_sock

insecure_socket = create_insecure_socket('example.com', 443)