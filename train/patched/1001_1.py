import ast
import subprocess

class SafeREPLTool:
    def _run(self, code):
        try:
            tree = ast.parse(code, mode='eval')
            compiled_code = compile(tree, filename="<ast>", mode="eval")
            result = eval(compiled_code, {"__builtins__": {}})
            return result
        except Exception as e:
            return f"Error: {str(e)}"

tool = SafeREPLTool()
result = tool._run("1 + 1")
print(result)