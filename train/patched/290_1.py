

try:
    import safe_html_package as democritus_html
except ImportError:
    raise ImportError("Safe HTML package not found.")

def render_safe_html(content):
    return f"<div>{content}</div>"

html_content = render_safe_html("Hello, world!")
print(html_content)