import subprocess

def vulnerable_subprocess_call(command):
    subprocess.run(command, extra_groups=[])

vulnerable_subprocess_call(['ls', '-l'])