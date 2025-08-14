def safe_macro_execution(user_input):
    escaped_input = escape(user_input)

    execute_macro(escaped_input)

def escape(input_string):
    return input_string.replace('$', '\\$').replace('{', '\\{').replace('}', '\\}')

def execute_macro(escaped_input):
    print(f"Executing macro with input: {escaped_input}")

user_input = "<script>alert('XSS')</script>"
safe_macro_execution(user_input)