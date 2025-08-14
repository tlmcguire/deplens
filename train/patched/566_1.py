
def secure_eval(user_input):
    if not is_safe_input(user_input):
        raise ValueError("Unsafe input detected")

    return process_input(user_input)

def is_safe_input(user_input):
    return user_input.isalnum()

def process_input(user_input):
    print(f"Processing safe input: {user_input}")

try:
    user_input = "exampleCommand"
    secure_eval(user_input)
except ValueError as e:
    print(e)