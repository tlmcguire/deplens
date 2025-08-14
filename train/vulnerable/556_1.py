class VulnerableExecutor:
    def execute_code(self, code):
        exec(code)

executor = VulnerableExecutor()

user_input = "__import__('os').system('echo Vulnerable!')"
executor.execute_code(user_input)