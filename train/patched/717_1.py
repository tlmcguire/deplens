from jinja2 import Markup, escape

def safe_urlize(text):
    return Markup(escape(text))

user_input = "Check this out: http://example.com!!!"
safe_output = safe_urlize(user_input)
print(safe_output)