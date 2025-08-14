from urllib.parse import urlparse, urlsplit

url = "http://[not-an-ipv6]:8080/path"

try:
    result = urlparse(url, allow_fragments=False)
    if result.hostname and '[' in result.hostname and ']' in result.hostname:

        host_part = result.hostname.strip('[]')
        try:
            import ipaddress
            ipaddress.ip_address(host_part)
        except ValueError:
            raise ValueError("Invalid IPv6 address format")

    print("Parsed URL:", result)
except ValueError as e:
    print("Error parsing URL:", e)

valid_url = "http://[2001:db8::1]:8080/path"
parsed_valid = urlparse(valid_url, allow_fragments=False)
print("Parsed valid URL:", parsed_valid)