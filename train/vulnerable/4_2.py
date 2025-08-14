import socket
import ssl

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server_address = ('localhost', 10023)
sock.bind(server_address)

sock.listen(1)

context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")
context.verify_mode = ssl.CERT_REQUIRED
context.load_verify_locations(cafile="client.crt")

connection, client_address = sock.accept()


secure_sock = None
try:
    secure_sock = context.wrap_socket(connection, server_side=True)

    data = secure_sock.recv(1024)
    print(data)
except ssl.SSLError as e:
    print(f"SSL Error: {e}")
finally:
    if secure_sock:
        secure_sock.close()
    connection.close()
    sock.close()