import os
import subprocess

def execute_user_code(user_code):

    try:
        restricted_env = {
            'PATH': '/usr/bin',
            'PYTHONUNBUFFERED': '1',
        }

        result = subprocess.run(
            ['python3', '-c', user_code],
            env=restricted_env,
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error: {result.stderr}"

    except Exception as e:
        return f"Execution failed: {str(e)}"

user_code = "print('Hello, World!')"