import urllib.request

response = urllib.request.urlopen('https://example.com')

print(response.read())