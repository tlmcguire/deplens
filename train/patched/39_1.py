import urllib3
import ssl

proxy_url = "https://myproxy.example.com:8080"

http = urllib3.PoolManager(
    proxy_url=proxy_url,
    ssl_cert_reqs=ssl.CERT_REQUIRED,
    cert_reqs='CERT_REQUIRED'
)

response = http.request('GET', 'https://example.com')

print(response.data.decode('utf-8'))