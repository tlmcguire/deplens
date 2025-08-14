
import urllib3

http = urllib3.PoolManager(disable_proxy=True)

response = http.request('GET', 'http://example.com')

print(response.data)