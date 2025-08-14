import os

def get_pid_info(pid):
    try:
        with open(f'/proc/{pid}/status') as f:
            return f.read()
    except FileNotFoundError:
        return None

def read_process_info(pid):
    proc_info = get_pid_info(pid)
    if proc_info:
        print(f"Process {pid} info:\n{proc_info}")
    else:
        print(f"No information found for PID {pid}")

pid = 1234
read_process_info(pid)