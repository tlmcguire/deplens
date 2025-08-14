import os
import subprocess

def vulnerable_execute(command):
    env = os.environ.copy()
    env['PATH'] = '/usr/local/bin:/usr/bin:/bin'

    result = subprocess.run(command, shell=True, env=env, capture_output=True, text=True)

    return result.stdout, result.stderr

command = "whoami"
stdout, stderr = vulnerable_execute(command)

print("Output:", stdout)
print("Error:", stderr)