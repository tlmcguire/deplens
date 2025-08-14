import subprocess

def process_metadata(metadata):
    command = metadata.get("command")

    allowed_commands = {"list": "ls", "current_dir": "pwd"}

    if command in allowed_commands:
        safe_command = allowed_commands[command]
        output = subprocess.check_output(safe_command, shell=True)
        return output
    return "Invalid command provided."