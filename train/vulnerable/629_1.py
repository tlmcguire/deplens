
def execute_user_code(code):
    exec(code)

user_code = "__import__('os').system('whoami')"
execute_user_code(user_code)