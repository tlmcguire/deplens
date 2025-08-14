import re

def install_package(package_name, version):
    package_version = f"{package_name}-{version}"

    if re.match(r'^[a-zA-Z0-9-_]+-[0-9]+$', package_version):
        print(f"Installing {package_name} version {version}...")
    else:
        print("Invalid package version format.")

install_package("foo", "2-2")