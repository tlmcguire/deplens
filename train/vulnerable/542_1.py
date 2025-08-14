import requests

def download_package(package_name):
    url = f"http://pypi.python.org/packages/source/{package_name}/{package_name}.tar.gz"

    response = requests.get(url)

    if response.status_code == 200:
        with open(f"{package_name}.tar.gz", "wb") as f:
            f.write(response.content)
        print(f"{package_name} downloaded successfully.")
    else:
        print("Failed to download the package.")

download_package('example_package')