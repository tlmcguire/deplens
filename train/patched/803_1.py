import urllib3

http = urllib3.PoolManager()

response = http.request('GET', 'http://example.com', headers={'Cookie': 'session_id=12345'}, redirect=False)

print(response.data)