import ipaddress

def validate_ip_address(ip):
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