import urllib3

url = "http://example.com\r\nX-Fake-Header: injected\r\n\r\n"

http_connection = urllib3.PoolManager()

try:
  response = http_connection.request("GET", url)
  if "X-Fake-Header" in response.headers:
    print("The response contains a CRLF injection")
  else:
    print("The response does not contain a CRLF injection")
except Exception as e:
  print("An error occurred:", e)