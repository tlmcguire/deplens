import subprocess
import shlex

def run_gcov(file_path):
    command = ["gcov", file_path]

    subprocess.Popen(command)

malicious_input = "file.c; cat /etc/passwd"
run_gcov(malicious_input)