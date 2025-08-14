import re

def safe_validate_link(url):
    pattern = re.compile(
        r'^(https?://)?(www\.)?([a-zA-Z0-9-]+(\.[a-zA-Z]{2,})+)(:[0-9]{1,5})?(/.*)?$'
    )
    return bool(pattern.match(url))

url_to_test = "http://example.com"
if safe_validate_link(url_to_test):
    print("Valid URL")
else:
    print("Invalid URL")