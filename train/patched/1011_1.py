import subprocess
import shlex

def safe_exec(command, metadata):
    sanitized_metadata = {key: str(value).replace('\n', '\r') for key, value in metadata.items()}

    safe_command = command.format(**sanitized_metadata)


    subprocess.run(shlex.split(safe_command), check=True)

metadata = {
    'filepath': 'example.mp4',
    'title': 'example title with & special chars',
}

command = 'echo {title} > {filepath}'

safe_exec(command, metadata)