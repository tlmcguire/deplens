from urllib.parse import urlparse
import requests

def fetch_url(url):
    parsed_url = urlparse(url)

    scheme = parsed_url.scheme
    netloc = parsed_url.netloc

    proxy_url = f"{scheme}://{netloc}"

    proxy_headers = {
        "Proxy-Authorization": "Basic QWxhZGprakdFRReGR5"
    }

    try:
        response = requests.get(url, proxies={"http": proxy_url, "https": proxy_url}, headers=proxy_headers)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
         print(f"Error fetching URL: {e}")
         return None

url = "http://example.com"
print(fetch_url(url))