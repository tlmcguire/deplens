import subprocess

def vulnerable_exec(command, metadata):
    command_to_run = command.format(**metadata)

    subprocess.run(command_to_run, shell=True)

metadata = {
    'filepath': 'example.mp4',
    'title': 'example title with & special chars',
}

command = 'echo {title} > {filepath}'

vulnerable_exec(command, metadata)