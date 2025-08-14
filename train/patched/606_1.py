import ast

def safe_eval(expr):
    return ast.literal_eval(expr)

def import_bvh(file_path):
    with open(file_path, 'r') as file:
        hierarchy_element = file.read()

        try:
            result = safe_eval(hierarchy_element)
        except (ValueError, SyntaxError) as e:
            print(f"Error processing the hierarchy element: {e}")