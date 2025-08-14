def execute_user_input(user_input):
    result = eval(user_input)
    return result

user_input = "__import__('os').system('ls')"
result = execute_user_input(user_input)
print(result)