import subprocess

def secure_install(package_name):
    try:
        subprocess.run(["pip", "install", "--no-index", "--find-links=https://my-private-repo.com/packages", package_name], check=True)
    except subprocess.CalledProcessError:
        print(f"Installing {package_name} from public repository")
        subprocess.run(["pip", "install", package_name], check=True)

secure_install("my-package")