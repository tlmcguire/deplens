def math_command(expression):
    result = eval(expression)
    return result

user_input = "2 + 2"
print(math_command(user_input))