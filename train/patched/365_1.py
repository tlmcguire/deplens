import urllib.request
import ssl

def fetch_data(url):
    ssl_context = ssl.create_default_context()

    response = urllib.request.urlopen(url, context=ssl_context)
    return response.read()

data = fetch_data("https://example.com/api")
print(data)