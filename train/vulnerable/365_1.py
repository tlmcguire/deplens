import urllib.request

def fetch_data(url):
    response = urllib.request.urlopen(url)
    return response.read()

data = fetch_data("https://example.com/api")
print(data)