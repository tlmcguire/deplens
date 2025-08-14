class PythonAstREPLTool:
    def _run(self, code):
        try:
            result = eval(code)
            return result
        except Exception as e:
            return f"Error: {str(e)}"

tool = PythonAstREPLTool()
result = tool._run("__import__('os').system('ls')")
print(result)