import subprocess

def run_command_with_secret(secret):
    try:
        result = subprocess.run(
            ['your_command', 'arg1', 'arg2'],
            env={'SECRET_ENV': secret},
            check=True,
            capture_output=True,
            text=True
        )
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"Command failed with error: {e.stderr}")

run_command_with_secret('my_secret_value')