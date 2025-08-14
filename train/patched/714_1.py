import bleach

def sanitize_html_input(user_input):
    allowed_tags = ['p', 'b', 'i', 'u', 'strong', 'em', 'a']
    allowed_attributes = {'a': ['href', 'title']}

    sanitized_input = bleach.clean(user_input, tags=allowed_tags, attributes=allowed_attributes)
    return sanitized_input

user_input = '<script>alert("XSS")</script><p>This is a <a href="http://example.com" title="Example">link</a>.</p>'
safe_input = sanitize_html_input(user_input)
print(safe_input)