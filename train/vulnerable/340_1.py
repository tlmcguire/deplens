import ssl
import urllib.request

context = ssl._create_unverified_context()

response = urllib.request.urlopen('https://swift.example.com', context=context)
data = response.read()
print(data)