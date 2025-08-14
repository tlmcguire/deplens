import ast

def safe_eval(expression):
    allowed_nodes = {
        ast.Expression,
        ast.BinOp,
        ast.UnaryOp,
        ast.Num,
        ast.Str,
        ast.Name,
        ast.Load,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.Mod,
        ast.Pow,
        ast.BitXor,
        ast.USub,
        ast.UAdd,
        ast.Compare,
        ast.Eq,
        ast.NotEq,
        ast.Lt,
        ast.LtE,
        ast.Gt,
        ast.GtE,
        ast.BoolOp,
        ast.And,
        ast.Or,
    }

    def _check_node(node):
        if type(node) not in allowed_nodes:
            raise ValueError("Disallowed expression")

    tree = ast.parse(expression, mode='eval')
    for node in ast.walk(tree):
        _check_node(node)

    return eval(compile(tree, filename='', mode='eval'))

user_input = "2 + 2"
result = safe_eval(user_input)
print(result)