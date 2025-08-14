import urllib.parse
import urllib.request

proxy_url = "http://example.com/cache"

url = "http://example.com/app?param1=value1;param2=value2"

parsed_url = urllib.parse.urlparse(url)
query_string = parsed_url.query

params = urllib.parse.parse_qs(query_string, separator=';')

new_query_string = urllib.parse.urlencode(params, quote_via=urllib.parse.quote_plus)


new_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query_string, parsed_url.fragment))

proxy_handler = urllib.request.ProxyHandler({"http": proxy_url})

opener = urllib.request.build_opener(proxy_handler)

urllib.request.install_opener(opener)

try:
    response = urllib.request.urlopen(new_url)
    print(response.read().decode())
except urllib.error.URLError as e:
    print(f"Error during request: {e}")
