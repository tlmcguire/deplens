import ast

def load_from_file(filename):
    with open(filename, 'rb') as f:
        return ast.literal_eval(f.read())