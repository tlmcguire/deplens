import urllib3

http = urllib3.PoolManager()

method = "GET"

url = "http://example.com/"

response = http.request(method, url, headers={"X-Injected-Header": "foo"})