import jinja2
from jinja2.sandbox import SandboxedEnvironment
from jinja2 import Environment, FileSystemLoader

def format_wrapper(value, format_string):
    if not isinstance(value, str):
       value = str(value)

    return value.format(format_string)



def create_sandbox_env():
    env = SandboxedEnvironment()
    env.filters['format_wrapper'] = format_wrapper
    return env


def render_template_fixed(template_string, context):
    env = create_sandbox_env()
    template = env.from_string(template_string)
    return template.render(context)


if __name__ == '__main__':

    vuln_template = '{{ malicious_string | format_wrapper(format_string)}}'

    malicious_string = '{0.__class__.__init__.__globals__[\'__builtins__\'][\'eval\']("import os; os.system(\'whoami\')")}'
    format_string = 'a'

    context = {
        'malicious_string': malicious_string,
        'format_string': format_string
    }

    try:
        print("Rendering template with exploit...")
        result = render_template_fixed(vuln_template, context)
        print(f"Rendered output: {result}")
    except Exception as e:
        print(f"Exception: {e}")

    safe_template = '{{ safe_string | format_wrapper(format_string) }}'
    safe_string = "Hello, {}!"
    safe_context = {
        'safe_string': safe_string,
        'format_string': "World"
    }

    print("Rendering a safe template...")
    result = render_template_fixed(safe_template, safe_context)
    print(f"Rendered output: {result}")
