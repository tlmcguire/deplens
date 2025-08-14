import ast

def load_rules(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    try:
      rules = ast.literal_eval(content)
    except (ValueError, SyntaxError):
      raise ValueError("Invalid Python literal in rules file")
    return rules
