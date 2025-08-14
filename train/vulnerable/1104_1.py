from jinja2 import Environment, FileSystemLoader

env = Environment(
    loader=FileSystemLoader('templates')
)

template = env.get_template('example_template.html')
output = template.render(user_input=user_input)