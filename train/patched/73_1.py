
import urllib.request
import re

def patched_function(url):
    from urllib.parse import urlparse, urlsplit
    parsed_url = urlsplit(url)
    if not parsed_url.scheme or not parsed_url.netloc:
        raise ValueError("Invalid URL format")

    pattern = r"^[a-z]+$"

    req = urllib.request.Request(url)

    response = urllib.request.urlopen(req)

    content = response.read().decode('utf-8')

    try:
        match = re.search(pattern, content)
        if match:
            return match.group()
    except re.error as e:
        return f"Error: {str(e)}"

url = "http://example.com/valid-content"
result = patched_function(url)