import re

def sanitize_template(template):
    allowed_pattern = re.compile(r'^[\w\s{}]+$')
    if not allowed_pattern.match(template):
        raise ValueError("Invalid template: contains unsafe characters.")
    return template

def configure_data_pipeline(template):
    sanitized_template = sanitize_template(template)

try:
    user_input_template = "{{ user_input }}"
    configure_data_pipeline(user_input_template)
except ValueError as e:
    print(e)