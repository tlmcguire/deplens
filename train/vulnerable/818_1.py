def execute_user_code(user_input):
    exec(user_input)

user_code = "os.system('echo Vulnerable!')"
execute_user_code(user_code)