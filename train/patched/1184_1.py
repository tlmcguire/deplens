import ast
import traceback

class SafePythonCodeTool:
    def execute_code(self, code):
        try:
            safe_code = ast.literal_eval(code)
            return safe_code
        except Exception as e:
            print(f"Error executing code: {traceback.format_exc()}")

tool = SafePythonCodeTool()
result = tool.execute_code("[1, 2, 3]")
print(result)