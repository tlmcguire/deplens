import os

def vulnerable_function(code):
    exec(code)

user_input = "os.system('echo Vulnerable!')"
vulnerable_function(user_input)