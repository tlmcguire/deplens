import urllib.request

def fetch_data(url):
    response = urllib.request.urlopen(url)
    return response.read()

url = "https://example.com/data"
data = fetch_data(url)
print(data)