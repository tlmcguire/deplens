import http.client

conn = http.client.HTTPConnection("example.com")

method = "GET\r\nX-Injected-Header: foo\r\n"

path = "/"

conn.request(method, path)