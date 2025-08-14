
import socket

def create_socket_pair():
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock1.bind(('localhost', 0))
    sock1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    port = sock1.getsockname()[1]

    sock2.connect(('localhost', port))

    sock1.listen(1)
    conn, _ = sock1.accept()

    sock1.close()

    return conn, sock2