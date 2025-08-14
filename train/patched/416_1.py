def parse_type_line(type_line):
    if not is_safe_input(type_line):
        raise ValueError("Unsafe input detected.")
    return type_line

def is_safe_input(type_line):
    allowed_types = ['int', 'float', 'str', 'list', 'dict']
    return any(type_line.startswith(allowed_type) for allowed_type in allowed_types)

user_input = "int"
result = parse_type_line(user_input)