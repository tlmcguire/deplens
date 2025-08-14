import urllib3

http = urllib3.PoolManager()

headers = {
    'Proxy-Authorization': 'Basic dXNlcm5hbWU6cGFzc3dvcmQ='
}

response = http.request('GET', 'http://example.com', headers=headers)

print(response.data)