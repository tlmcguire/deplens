import urllib3

http = urllib3.PoolManager()

proxy = "https://malicious.com:8080"

url = "https://example.com"

try:
    response = http.request("GET", url, retries=False, timeout=10, preload_content=False, proxy_url=proxy)
except urllib3.exceptions.MaxRetryError as e:
    print(f"Error during request: {e}")
