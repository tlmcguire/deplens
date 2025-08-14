import os
import subprocess

def secure_execute(command):
    safe_env = {
        'PATH': '/usr/bin:/bin',
        'HOME': os.path.expanduser('~'),
    }

    result = subprocess.run(command, shell=False, env=safe_env, capture_output=True, text=True)

    return result.stdout, result.stderr

command = ["whoami"]
stdout, stderr = secure_execute(command)

print("Output:", stdout)
print("Error:", stderr)