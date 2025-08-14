import socket

def vulnerable_readline(sock):
    return sock.recv(4096).decode('utf-8')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(('example.com', 80))
    s.sendall(b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
    response = vulnerable_readline(s)
    print(response)