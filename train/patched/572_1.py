import certifi
import ssl
import socket

context = ssl.create_default_context(cafile=certifi.where())

with socket.socket() as sock:
    with context.wrap_socket(sock, server_hostname='example.com') as s:
        s.connect(('example.com', 443))
        print(s.recv(1024))