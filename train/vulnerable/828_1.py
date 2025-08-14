
def render_button(user_input):
    return f'<button onclick="{user_input}">Cancel and return to page</button>'

user_input = "returnToPage(); alert('XSS Vulnerability!');"
html_output = render_button(user_input)
print(html_output)