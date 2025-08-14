from urllib.parse import urlparse, urlsplit

url = "http://[not-an-ipv6]:8080/path"

parsed_url = urlparse(url)
print("Parsed URL:", parsed_url)

if parsed_url.hostname:
    print("Hostname:", parsed_url.hostname)
else:
    print("No valid hostname found.")