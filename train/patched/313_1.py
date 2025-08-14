import ssl
import socket

def create_ssl_connection(host, port):
    context = ssl.create_default_context()
    connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
    try:
        connection.connect((host, port))
        return connection
    except ssl.SSLError as e:
        print(f"SSL error: {e}")
        return None

host = "example.com"
port = 443
conn = create_ssl_connection(host, port)
if conn:
    print("SSL connection established")
else:
    print("SSL connection failed")