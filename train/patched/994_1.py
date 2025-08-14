
def safe_execute(script):
    allowed_builtins = {
        'len': len,
        'str': str,
        'int': int,
    }

    exec_globals = {'__builtins__': allowed_builtins}

    try:
        exec(script, exec_globals)
    except Exception as e:
        print(f"An error occurred: {e}")

user_script = """
# This script should be limited in functionality
result = len("Hello, World!")
"""

safe_execute(user_script)