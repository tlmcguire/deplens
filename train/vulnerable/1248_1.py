import os
import subprocess

def execute_command_and_log(command):
    """Executes a command and logs the output to a temporary file."""
    try:

        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()

        log_file = "/tmp/framer.txt"
        with open(log_file, "a") as f:
            f.write(f"Command: {command}\n")
            f.write(f"Stdout:\n{stdout.decode()}\n")
            f.write(f"Stderr:\n{stderr.decode()}\n")
            f.write("-" * 20 + "\n")
    except Exception as e:
        print(f"Error executing command: {e}")

def main():


    commands_to_run = [
        "echo 'This is a test command'",
        "ls -la /home/user/",
        "cat /etc/passwd",
        "printenv",
        "ssh -v user@remote.server cat secret_file",
        "git config --global --list"
    ]

    for command in commands_to_run:
      execute_command_and_log(command)


if __name__ == "__main__":
    main()