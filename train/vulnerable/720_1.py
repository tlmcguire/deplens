import subprocess

def insecure_chpasswd(username, password):
    command = f"echo '{username}:{password}' | chpasswd"
    subprocess.run(command, shell=True, check=True)

insecure_chpasswd('root', '!')