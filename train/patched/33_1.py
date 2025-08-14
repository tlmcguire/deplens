import ipaddress

def validate_ip_address(ip):
    parts = ip.split(".")

    if len(parts) != 4:
        return False

    for part in parts:
        part = part.lstrip("0") or "0"

        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False

    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

ip = "0127.0.0.1"
if validate_ip_address(ip):
    print(f"{ip} is a valid IP address")
else:
    print(f"{ip} is not a valid IP address")