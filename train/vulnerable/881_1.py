def execute_macro(user_input):
    eval(user_input)

user_input = "print('This is a malicious command!')"
execute_macro(user_input)