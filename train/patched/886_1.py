import re

def safe_execute(user_input):
    sanitized_input = re.sub(r'[^a-zA-Z0-9_]', '', user_input)

    allowed_commands = ['function1', 'function2']
    if sanitized_input in allowed_commands:
        return execute_command(sanitized_input)
    else:
        raise ValueError("Invalid command")

def execute_command(command):
    return f"Executing {command}"

try:
    user_input = "function1"
    result = safe_execute(user_input)
    print(result)
except ValueError as e:
    print(e)