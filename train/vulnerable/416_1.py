def parse_type_line(type_line):
    return eval(type_line)

user_input = "__import__('os').system('ls')"
result = parse_type_line(user_input)