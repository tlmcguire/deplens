class PythonCodeTool:
    def execute_code(self, code):
        try:
            exec(code)
        except Exception as e:
            print(f"Error executing code: {e}")

tool = PythonCodeTool()
tool.execute_code("import os; os.system('ls')")