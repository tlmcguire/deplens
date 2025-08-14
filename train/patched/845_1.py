
def sanitize_input(user_input):
    forbidden_patterns = ['$', '{', '}', '(', ')', 'import', 'exec', 'eval']
    for pattern in forbidden_patterns:
        if pattern in user_input:
            raise ValueError("Invalid input detected!")

    return user_input

def execute_macro(user_input):
    sanitized_input = sanitize_input(user_input)

    print(f"Executing macro with sanitized input: {sanitized_input}")

try:
    user_input = "some_safe_macro_input"
    execute_macro(user_input)
except ValueError as e:
    print(e)