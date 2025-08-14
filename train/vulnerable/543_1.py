from jinja2 import Environment, FileSystemLoader

env = Environment(
    loader=FileSystemLoader('templates')
)

def render_template(template_name, context):
    template = env.get_template(template_name)
    return template.render(context)

if __name__ == "__main__":
    user_input = input("Enter template name: ")
    user_context = {
        'user_input': user_input
    }
    output = render_template(user_input, user_context)
    print(output)