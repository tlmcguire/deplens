import urllib.parse

proxy_url = "http://example.com/cache"

url = "http://example.com/app?param1=value1;param2=value2"

proxy_handler = urllib.request.ProxyHandler({"http": proxy_url})

opener = urllib.request.build_opener(proxy_handler)

urllib.request.install_opener(opener)

response = urllib.request.urlopen(url)

print(response.read().decode())
