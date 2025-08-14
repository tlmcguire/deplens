def vulnerable_function(user_input):
    result = eval(user_input)
    return result

user_input = "__import__('os').system('ls')"
output = vulnerable_function(user_input)