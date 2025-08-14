import urllib3

proxy_url = "https://myproxy.example.com:8080"

http = urllib3.PoolManager(proxy_url)

response = http.request('GET', 'https://example.com')

print(response.data)