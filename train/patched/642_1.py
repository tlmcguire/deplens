import ssl
import qpid.messaging

def create_ssl_connection(host, port):
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    connection = qpid.messaging.Connection(host, port, ssl_context=context, transport='ssl')
    connection.open()
    return connection

if __name__ == "__main__":
    host = 'example.com'
    port = 5671
    try:
      connection = create_ssl_connection(host, port)
      print("SSL Connection established successfully")
    except qpid.messaging.ConnectionError as e:
      print(f"Error establishing SSL Connection: {e}")