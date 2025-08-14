import subprocess

def safe_execute_command(command):
    allowed_commands = ['ls', 'pwd', 'echo']
    command_parts = command.split()

    if command_parts[0] in allowed_commands:
        result = subprocess.run(command_parts, capture_output=True, text=True)
        return result.stdout
    else:
        raise ValueError("Command not allowed")

try:
    output = safe_execute_command("ls")
    print(output)
except ValueError as e:
    print(e)