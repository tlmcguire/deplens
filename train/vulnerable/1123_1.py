def execute_code(code):
    exec(code)

malicious_code = "__import__('os').system('echo Vulnerable!')"

execute_code(malicious_code)