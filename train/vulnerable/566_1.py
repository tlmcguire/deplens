def execute_user_code(user_input):
    exec(user_input)

user_input = "__import__('os').system('ls')"
execute_user_code(user_input)