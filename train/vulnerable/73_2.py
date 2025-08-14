import urllib.request

server = "http://evil.com/"

request = urllib.request.Request(server)

auth_handler = urllib.request.AbstractBasicAuthHandler()

opener = urllib.request.build_opener(auth_handler)

response = opener.open(request)