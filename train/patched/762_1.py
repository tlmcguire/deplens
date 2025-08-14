import os
import pwd

def get_pid_info(pid):
    try:
        with open(f'/proc/{pid}/status') as f:
            status_info = f.read()
        uid = int(status_info.split('Uid:')[1].split()[0])
        user = pwd.getpwuid(uid).pw_name
        return user, status_info
    except FileNotFoundError:
        return None, None

def secure_read_proc(pid):
    user, status_info = get_pid_info(pid)
    if user is None:
        raise ValueError("Invalid PID or process does not exist.")

    current_user = pwd.getpwuid(os.getuid()).pw_name
    if user != current_user:
        raise PermissionError("Attempt to read information from a process owned by another user.")

    return status_info

try:
    pid = 1234
    proc_info = secure_read_proc(pid)
    print(proc_info)
except Exception as e:
    print(f"Error: {e}")