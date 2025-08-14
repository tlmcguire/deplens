import ast

def safe_eval(expr):
    node = ast.parse(expr, mode='eval')

    for n in ast.walk(node):
        if not isinstance(n, (ast.Expression, ast.Num, ast.Str, ast.List, ast.Dict, ast.Tuple, ast.Name, ast.BinOp, ast.UnaryOp, ast.Compare, ast.Call)):
            raise ValueError("Unsafe expression detected")

    return eval(compile(node, '<string>', mode='eval'))

def process_schema(schema_lines):
    for line in schema_lines:
        try:
            result = safe_eval(line)
        except Exception as e:
            print(f"Error processing line '{line}': {e}")

schema = [
    "1 + 2",
    "'hello'.upper()",
    "__import__('os').system('ls')"
]

process_schema(schema)