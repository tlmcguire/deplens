import ast
import sys

def safe_eval(expr):
    allowed_nodes = {
        ast.Expression,
        ast.Num,
        ast.Str,
        ast.List,
        ast.Tuple,
        ast.Name,
        ast.BinOp,
        ast.UnaryOp,
        ast.Load,
        ast.Store,
        ast.Call,
        ast.Attribute,
    }

    class SafeVisitor(ast.NodeVisitor):
        def visit(self, node):
            if type(node) not in allowed_nodes:
                raise ValueError("Unsafe operation detected.")
            return super().visit(node)

    tree = ast.parse(expr, mode='eval')
    SafeVisitor().visit(tree)

    return eval(compile(tree, filename="<ast>", mode="eval"), {"__builtins__": None}, {})

try:
    result = safe_eval("1 + 2")
    print(result)

except ValueError as e:
    print(e)