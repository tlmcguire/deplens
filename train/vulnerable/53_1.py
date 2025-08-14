import http.client

def vulnerable_function():
    conn = http.client.HTTPConnection("example.com")
    conn.request("GET", "/")

    response = conn.getresponse()
    response.read()

vulnerable_function()