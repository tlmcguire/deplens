import hmac

def check_email_domain(email, domain):
    email = email.encode()
    domain = domain.encode()
    email_parts = email.split(b'@')
    if len(email_parts) != 2:
        return False
    email_domain = email_parts[-1]
    return hmac.compare_digest(email_domain, domain)

print(check_email_domain("alice@company.example.com", "company.example.com"))
print(check_email_domain("bob@company.example.com", "company.example.com"))
print(check_email_domain("charlie@evil.com", "company.example.com"))
print(check_email_domain("alice@evil.com<alice@company.example.com>", "company.example.com"))