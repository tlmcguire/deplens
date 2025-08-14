def execute_user_code(user_code):
    exec(user_code)

user_code = "import os; os.system('echo Vulnerable!')"
execute_user_code(user_code)