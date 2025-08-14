import subprocess

def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error: Command '{command}' failed with return code {e.returncode}. Output:\n{e.stderr}"


try:
    output = execute_command('ls')
    print(output)

    output = execute_command('rm -rf /')
    print(output)
except Exception as e:
    print(e)