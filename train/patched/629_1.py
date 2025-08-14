
import ast
import logging

def safe_exec(code, globals=None, locals=None):
    safe_builtins = {
        'print': print,
    }

    if globals is None:
        globals = {}
    if locals is None:
        locals = {}

    try:
        code_ast = ast.parse(code, mode='exec')
        for node in ast.walk(code_ast):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                raise ValueError("Imports are not allowed.")
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                     if node.func.id not in safe_builtins:
                        raise ValueError("Unsafe function call detected.")
                else:
                    raise ValueError("Unsafe function call detected.")

        exec(compile(code_ast, filename="<ast>", mode="exec"), {**globals, **safe_builtins}, locals)
    except Exception as e:
        logging.error(f"Error executing code: {e}")

user_code = "print('Hello, World!')"
safe_exec(user_code)