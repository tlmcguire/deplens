import subprocess

def vulnerable_python_execution():
    command = 'your_script.py'
    subprocess.run(['python', command])

vulnerable_python_execution()