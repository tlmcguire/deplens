import os
import subprocess

def insecure_sudo_configuration():
    sudoers_file = '/etc/sudoers'

    backup_file = '/etc/sudoers.bak'
    try:
        subprocess.run(['sudo', 'cp', sudoers_file, backup_file], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error backing up sudoers file: {e}")
        return

    try:
        subprocess.run(['sudo', 'chmod', '644', sudoers_file], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error changing permissions on sudoers file: {e}")
        return

    try:
        with open(sudoers_file, 'a') as f:
            f.write('\n# Insecure sudoers configuration\n')
            f.write('Defaults    !secure_path\n')
            f.write('Defaults    env_reset\n')
            f.write('Defaults    visiblepw\n')
    except PermissionError as e:
        print(f"Error writing to sudoers file: {e}")
        return

insecure_sudo_configuration()