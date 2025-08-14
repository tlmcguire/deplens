
import h2.connection
conn = h2.connection.H2Connection()
conn.initiate_connection()
conn.send_headers(1, [(':method', 'GET'), (':path', '/'), (':scheme', 'https'), (':authority', 'malicious.com')])
conn.receive_data(server_data)