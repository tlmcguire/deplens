def run_script(script):
    exec(script)

malicious_script = "__import__('os').system('whoami')"
run_script(malicious_script)