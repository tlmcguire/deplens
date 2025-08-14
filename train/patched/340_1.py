import ssl
import urllib.request

context = ssl.create_default_context()


response = urllib.request.urlopen('https://swift.example.com', context=context)
data = response.read()
print(data)