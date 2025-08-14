import urllib3

http = urllib3.PoolManager()

url = 'http://example.com/some_endpoint'
body = 'sensitive_data=secret_value'

response = http.request('POST', url, body=body)

print(response.data)