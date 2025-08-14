import bleach

def sanitize_uri(input_uri):
    allowed_protocols = ['http', 'https', 'ftp']
    sanitized_uri = bleach.clean(input_uri, tags=[], attributes={}, styles=[], strip=True)

    if any(sanitized_uri.startswith(protocol + '://') for protocol in allowed_protocols):
        return sanitized_uri
    else:
        raise ValueError("Invalid URI: Only HTTP, HTTPS, and FTP protocols are allowed.")

try:
    user_input = "javascript:alert('XSS')"
    safe_uri = sanitize_uri(user_input)
    print("Sanitized URI:", safe_uri)
except ValueError as e:
    print(e)