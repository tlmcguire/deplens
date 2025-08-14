import ipaddress

def is_external_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_global
    except ValueError:
        return False

def make_request_to_domain(domain, ip):
    if not is_external_ip(ip):
        raise ValueError("Request to internal IP addresses is not allowed.")

    print(f"Making request to {domain} from external IP {ip}")

try:
    make_request_to_domain("https://example.com", "192.0.2.1")
    make_request_to_domain("https://example.com", "10.0.0.1")
except ValueError as e:
    print(e)