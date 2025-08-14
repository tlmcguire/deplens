import os

def sanitize_input(user_input):
    sanitized_input = user_input.replace(";", "").replace("'", "").replace("\"", "").replace("`", "")
    return sanitized_input

def execute_user_code(user_input):
    safe_input = sanitize_input(user_input)

    try:
        print(f"Executing: {safe_input}")
    except Exception as e:
        print(f"Error executing code: {e}")

user_input = "print('Hello, World!'); os.system('rm -rf /')"
execute_user_code(user_input)