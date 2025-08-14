def execute_user_code(user_input):
    eval(user_input)

user_input = "__import__('os').system('ls')"
execute_user_code(user_input)