
def safe_render_button():
    button_label = escape_html("Cancel and return to page")
    return f'<button onclick="returnToPage()">{button_label}</button>'

def escape_html(text):
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;"))

html_output = safe_render_button()
print(html_output)