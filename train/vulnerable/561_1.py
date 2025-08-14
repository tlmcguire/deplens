def execute_script(script):
    exec(script)

user_input = "import os; os.system('echo Vulnerable!')"
execute_script(user_input)