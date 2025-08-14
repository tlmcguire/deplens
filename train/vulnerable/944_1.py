def execute_user_code(user_input):
    try:
        result = eval(user_input)
        return result
    except Exception as e:
        return str(e)

user_input = "__import__('os').system('ls')"
output = execute_user_code(user_input)
print("Output:", output)