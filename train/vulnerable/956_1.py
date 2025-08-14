from jinja2 import Environment

env = Environment(autoescape=False)

template = env.from_string("""
<div {{ attributes | xmlattr }}></div>
""")

unsafe_attributes = {
    'onclick': 'alert("XSS Attack!")',
    'style': 'background-color: red;'
}

rendered = template.render(attributes=unsafe_attributes)
print(rendered)