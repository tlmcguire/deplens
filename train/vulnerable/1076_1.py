import ipaddress

incorrect_private_ip = ipaddress.IPv4Address('10.0.0.1')
incorrect_global_ip = ipaddress.IPv4Address('8.8.8.8')

print(f"{incorrect_private_ip} is private: {incorrect_private_ip.is_private}")
print(f"{incorrect_global_ip} is global: {incorrect_global_ip.is_global}")

incorrect_private_ipv6 = ipaddress.IPv6Address('fd00::1')
incorrect_global_ipv6 = ipaddress.IPv6Address('2001:4860:4860::8888')

print(f"{incorrect_private_ipv6} is private: {incorrect_private_ipv6.is_private}")
print(f"{incorrect_global_ipv6} is global: {incorrect_global_ipv6.is_global}")