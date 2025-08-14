def execute_script(script_code):
    exec(script_code)

user_input = "__import__('os').system('ls')"
execute_script(user_input)