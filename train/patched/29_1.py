from urllib.parse import urlparse, urlunparse
import requests

def fetch_url(url):
    parsed_url = urlparse(url)

    sanitized_path = parsed_url.path.replace("\r", "").replace("\n", "")
    sanitized_url = urlunparse((parsed_url.scheme, parsed_url.netloc, sanitized_path, parsed_url.params, parsed_url.query, parsed_url.fragment))

    scheme = parsed_url.scheme
    netloc = parsed_url.netloc

    proxy_url = f"{scheme}://{netloc}"

    proxy_headers = {
        "Proxy-Authorization": "Basic QWxhZGprakdFRReGR5"
    }

    response = requests.get(sanitized_url, proxies={"http": proxy_url, "https": proxy_url})

    return response.text

url = "http://example.com\r\nProxy-Authorization: Basic injected-credentials"
print(fetch_url(url))