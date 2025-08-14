import os

def execute_command(command):
    raise NotImplementedError("Command execution is not allowed in this environment.")

def vulnerable_function(code):
    exec(code)

def safe_function(code):
    allowed_commands = ["print('Hello, World!')"]
    if code in allowed_commands:
        exec(code)
    else:
        raise ValueError("Unauthorized command.")