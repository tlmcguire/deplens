def safe_execute_code(user_input):
    sanitized_input = escape_user_input(user_input)

    exec_context = {}

    try:
        exec(sanitized_input, exec_context)
    except Exception as e:
        print(f"Error executing code: {e}")

def escape_user_input(input_code):
    dangerous_chars = [';', 'import', 'exec', 'eval', '__', 'os', 'sys']
    for char in dangerous_chars:
        input_code = input_code.replace(char, '')
    return input_code

user_code = "print('Hello, World!')"
safe_execute_code(user_code)