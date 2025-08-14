import requests
r = requests.get('https://example.com', auth=('user', 'pass'))
print(r.status_code)