import urllib3

def fetch_url(url):
    http = urllib3.PoolManager()
    response = http.request('GET', url)
    return response.data

url = "http://example.com@" * 1000
try:
    data = fetch_url(url)
    print(data)
except Exception as e:
    print(f"Error: {e}")