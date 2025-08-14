import socket

def create_socket_pair():
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock1.bind(('localhost', 0))
    sock2.bind(('localhost', 0))

    port = sock1.getsockname()[1]

    sock2.connect(('localhost', port))

    return sock1, sock2

sock1, sock2 = create_socket_pair()
print("Socket pair created (vulnerable to connection race).")