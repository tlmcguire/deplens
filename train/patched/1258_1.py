
import ast

class RestrictedPythonVisitor(ast.NodeVisitor):
    def __init__(self):
        self.allowed_nodes = (
            ast.Module,
            ast.Expr,
            ast.Name,
            ast.Load,
            ast.Constant,
            ast.BinOp,
            ast.Add,
            ast.Sub,
            ast.Mult,
            ast.Div,
            ast.FloorDiv,
            ast.Mod,
            ast.Pow,
            ast.USub,
            ast.UAdd,
            ast.Call,
            ast.Attribute,
            ast.Subscript,
            ast.Index,
            ast.List,
            ast.Tuple,
            ast.Dict,
        )
        self.restricted_nodes = (ast.Try,)

    def visit(self, node):
        if not isinstance(node, self.allowed_nodes):
            if isinstance(node, self.restricted_nodes):
                raise TypeError(f"Node type '{type(node).__name__}' is restricted.")
            else:
               raise TypeError(f"Node type '{type(node).__name__}' is not allowed.")
        return super().generic_visit(node)


def safe_eval(code):
  """Evaluates python code with restricted operations."""
  try:
      tree = ast.parse(code)
  except SyntaxError as e:
      raise ValueError(f"Syntax error in code: {e}")

  visitor = RestrictedPythonVisitor()
  visitor.visit(tree)

  compiled_code = compile(tree, filename="<string>", mode="exec")
  exec(compiled_code, {})
  return eval(code, {})

if __name__ == '__main__':
    try:
        safe_eval("try: pass\nexcept*: pass")
    except TypeError as e:
        print(f"Error when using try/except*: {e}")

    try:
        safe_eval("1 + 2")
        print(f"Successful evalution of an allowed expression")
    except Exception as e:
        print(f"Error during successful evalution: {e}")

    try:
       safe_eval("[1, 2, 3]")
       print(f"Successful evalution of a list")
    except Exception as e:
       print(f"Error during successful evalution of a list: {e}")