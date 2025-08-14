import email.utils

malicious_input = "A" * 10**6 + "@example.com"

try:
    result = email.utils.parseaddr(malicious_input)
except RecursionError as e:
    print(f"RecursionError: {e}")
