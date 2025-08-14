import subprocess

def safe_snyk_test(command_args):
    allowed_args = ['--all-projects', '--json', '--file', '--path']
    for arg in command_args:
        if arg not in allowed_args:
            raise ValueError(f"Unsafe argument detected: {arg}")

    command = ['snyk', 'test'] + command_args
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout

try:
    output = safe_snyk_test(['--all-projects'])
    print(output)
except ValueError as e:
    print