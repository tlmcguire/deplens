def execute_code(user_input):
    exec(user_input)

user_code = "print('Executing arbitrary code!')"
execute_code(user_code)