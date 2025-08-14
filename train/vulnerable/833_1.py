
def execute_macro(user, macro_code):
    exec(macro_code)

user = get_current_user()
macro_input = "import os; os.system('echo Vulnerable!')"
execute_macro(user, macro_input)