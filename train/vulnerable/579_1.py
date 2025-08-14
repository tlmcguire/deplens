import bleach

def unsafe_sanitize_uri(input_uri):
    sanitized_uri = bleach.clean(input_uri, tags=[], attributes={}, styles=[], strip=True)
    return sanitized_uri

user_input = "javascript:alert('XSS')"
unsafe_uri = unsafe_sanitize_uri(user_input)
print("Sanitized URI:", unsafe_uri)