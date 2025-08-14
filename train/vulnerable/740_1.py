from jinja2 import Environment, FileSystemLoader

env = Environment(
    loader=FileSystemLoader('templates')
)

def vulnerable_render(template_name, context):
    template = env.get_template(template_name)
    return template.render(context)

class Resource:
    def db(self):
        return "Database access"

if __name__ == "__main__":
    resource = Resource()
    user_context = {
        'resource': resource,
        'unsafe_variable': '{{ resource.db() }}'
    }
    output = vulnerable_render('example_template.html', user_context)
    print(output)