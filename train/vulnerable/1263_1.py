from urllib.parse import urlparse, urlsplit

url_with_brackets = "http://[example]domain.com/path"

parsed_url_split = urlsplit(url_with_brackets)
parsed_url_parse = urlparse(url_with_brackets)

print("urlsplit:", parsed_url_split)
print("urlparse:", parsed_url_parse)