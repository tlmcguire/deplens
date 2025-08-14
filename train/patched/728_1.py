import re
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator

def validate_ip_address(ip):
    ipv4_pattern = re.compile(r'^(?!0)([1-9]\d{0,2}|0)(\.(?!0)([1-9]\d{0,2}|0)){3}$')

    if not ipv4_pattern.match(ip):
        raise ValidationError(f"{ip} is not a valid IPv4 address.")


try:
    validate_ip_address("192.168.1.1")
    validate_ip_address("192.168.01.1")
except ValidationError as e:
    print(e)