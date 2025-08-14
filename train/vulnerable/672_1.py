import urllib.request

server_url = 'https://example.com/api'

response = urllib.request.urlopen(server_url)
data = response.read()
print(data)