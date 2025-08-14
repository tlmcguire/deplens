import os
import sys
import logging

def secure_path_setup():
    current_path = os.environ.get('PATH', '')

    secure_directories = [
        r'C:\Python27',
        r'C:\Python27\Scripts'
    ]

    for directory in secure_directories:
        if directory in current_path:
             logging.warning(f"Warning: {directory} is in the PATH. This may pose a security risk.")

    safe_directories = [
        r'C:\Windows\system32',
        r'C:\Windows',
        r'C:\Windows\System32\Wbem',
        r'C:\Windows\System32\WindowsPowerShell\v1.0'
    ]

    safe_path = os.pathsep.join(safe_directories)

    os.environ['PATH'] = safe_path

    current_path_after_update = os.environ.get('PATH', '')
    for directory in secure_directories:
        if directory in current_path_after_update:
            logging.error(f"Error: {directory} is still in the PATH after update")

if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
    secure_path_setup()
