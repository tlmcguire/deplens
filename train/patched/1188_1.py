import socket

def safe_readline(sock):
    max_length = 1024
    data = sock.recv(max_length)
    if len(data) >= max_length:
        raise ValueError("Input too long")
    return data.decode('utf-8')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(('example.com', 80))
    s.sendall(b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
    response = safe_readline(s)
    print(response)