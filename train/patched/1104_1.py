from jinja2 import Environment, FileSystemLoader, select_autoescape

env = Environment(
    loader=FileSystemLoader('templates'),
    autoescape=select_autoescape(['html', 'xml'])
)

template = env.get_template('example_template.html')
output = template.render(user_input=safe_user_input)