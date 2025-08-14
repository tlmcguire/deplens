import ast

def safe_load_rules(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    try:
        rules = ast.literal_eval(content)
    except (SyntaxError, ValueError):
        raise ValueError("Invalid rules format")
    return rules
