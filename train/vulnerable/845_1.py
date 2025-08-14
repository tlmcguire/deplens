
def execute_macro(user_input):
    exec(user_input)

user_input = "import os; os.system('whoami')"
execute_macro(user_input)