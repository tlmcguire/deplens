
import hyper
conn = hyper.HTTP20Connection('malicious.com')
conn.request('GET', '/')
response = conn.get_response()