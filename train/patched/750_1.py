
from Cheetah.Template import Template

def render_template(template_string, **context):
    safe_context = {key: str(value) for key, value in context.items()}
    template = Template(template_string, searchList=[safe_context])
    return str(template)

template_string = "Hello, $name!"
context = {'name': 'World'}
output = render_template(template_string, **context)
print(output)