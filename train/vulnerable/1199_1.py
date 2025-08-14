import os

def vulnerable_execute(script_path):
    exec(open(script_path).read())

if __name__ == "__main__":
    script_to_run = "malicious_script.py"
    vulnerable_execute(script_to_run)