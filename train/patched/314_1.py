
import requests

def safe_fetch_url(url):
    trusted_sources = ["https://example.com", "https://another-trusted-source.com"]
    if any(url.startswith(source) for source in trusted_sources):
        response = requests.get(url)
        return response.text
    else:
        raise ValueError("Untrusted URL!")

try:
    content = safe_fetch_url("https://example.com/resource")
    print(content)
except ValueError as e:
    print(e)