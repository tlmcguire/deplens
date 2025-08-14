import urllib3

url = "http://example.com/" + "%20" * 1000000

http = urllib3.PoolManager()

response = http.request("GET", url)