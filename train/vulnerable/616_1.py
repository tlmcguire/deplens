import re

def normalize_url(url):
    pattern = r'^(https?://)?(www\.)?([a-zA-Z0-9.-]+)(/.*)?$'

    match = re.match(pattern, url)
    if match:
        scheme = match.group(1) or 'http://'
        domain = match.group(3)
        path = match.group(4) or '/'
        return f"{scheme}{domain}{path}"
    else:
        raise ValueError("Invalid URL")

try:
    print(normalize_url("http://example.com/" + "a" * 10000 + "/path"))
except ValueError as e:
    print(e)