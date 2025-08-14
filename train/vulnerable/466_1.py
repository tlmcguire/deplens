def evaluate_expression(user_input):
    result = eval(user_input)
    return result

user_input = "1 + 2; os.system('cat /etc/passwd')"
output = evaluate_expression(user_input)