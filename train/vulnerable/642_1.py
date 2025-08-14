import qpid.messaging

def create_connection(host, port, qpid_protocol):
    try:
        connection = qpid.messaging.Connection(host=host, port=port, protocol=qpid_protocol)
        connection.open()
        return connection
    except qpid.messaging.exceptions.ConnectionError as e:
        print(f"Error creating connection: {e}")
        return None


if __name__ == "__main__":
    host = 'example.com'
    port = 5671
    qpid_protocol = 'ssl'
    connection = create_connection(host, port, qpid_protocol)
    if connection:
        print("Connection successful")
        connection.close()
    else:
      print("Connection failed")