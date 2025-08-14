import subprocess
import shlex

def process_metadata(metadata):
    command = metadata.get("command")

    if command:
        try:
            command_list = shlex.split(command)
            output = subprocess.check_output(command_list)
            return output
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            return f"Error executing command: {e}"
    return "No command provided."