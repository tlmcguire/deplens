def safe_render(input_data):
    escaped_data = escape(input_data)
    return render_page(escaped_data)

def escape(data):
    return data.replace("<", "&lt;").replace(">", "&gt;").replace("&", "&amp;")

def render_page(content):
    return f"<html><body>{content}</body></html>"