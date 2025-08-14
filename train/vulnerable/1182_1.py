import subprocess

def vulnerable_install(package_name):
    subprocess.run(["pip", "install", package_name], check=True)

vulnerable_install("malicious-package")