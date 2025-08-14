
import ast

def safe_eval(user_input):
    allowed_nodes = {
        ast.Expression,
        ast.Num,
        ast.Str,
        ast.List,
        ast.Tuple,
        ast.Dict,
        ast.NameConstant,
        ast.UnaryOp,
        ast.BinOp,
        ast.Compare,
        ast.BoolOp,
        ast.IfExp,
        ast.Call,
        ast.Attribute,
        ast.Subscript,
    }

    tree = ast.parse(user_input, mode='eval')

    for node in ast.walk(tree):
        if type(node) not in allowed_nodes:
            raise ValueError("Unsafe expression")

    return eval(compile(tree, filename='', mode='eval'))

try:
    result = safe_eval("2 + 2")
    print(result)
except ValueError as e:
    print(e)

try:
    result = safe_eval("__import__('os').system('ls')")
    print(result)
except ValueError as e:
    print(e)