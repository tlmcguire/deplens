import re

url_pattern = re.compile(
    r'^(https?://)?(www\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}(/[^\s]*)?$'
)

def is_valid_url(url):
    return bool(url_pattern.match(url))

test_urls = [
    "http://example.com",
    "https://www.example.com",
    "www.example.com",
    "example.com",
    "http://example.com/path/to/resource?query=1&other_query=2",
    "http://example.com/" + "a" * 1000 + ".com"
]

for url in test_urls:
    print(f"{url}: {is_valid_url(url)}")