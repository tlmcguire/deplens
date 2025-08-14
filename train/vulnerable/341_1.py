from markdown2 import markdown

def render_markdown(user_input):
    html_output = markdown(user_input)
    return html_output

user_input = "<script>alert('XSS');</script>"
output = render_markdown(user_input)
print(output)