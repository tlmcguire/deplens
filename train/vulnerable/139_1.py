
import ssl
import socket
host = "example.com"
port = 443
context = ssl.create_default_context()
sock = socket.create_connection((host, port))
ssock = context.wrap_socket(sock, server_hostname=host)
print(ssock.cipher())
ssock.sendall(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
data = ssock.recv(1024)
print(data)
ssock.close()