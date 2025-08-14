import re

def vulnerable_parse_index_url(url):
    pattern = r'^(https?://.*)$'
    match = re.match(pattern, url)
    if match:
        return match.group(0)
    else:
        raise ValueError("Invalid index server URL")

try:
    url = "https://example.com/index"
    print(vulnerable_parse_index_url(url))
except ValueError as e:
    print(e)