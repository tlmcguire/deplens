import requests
import hashlib

def download_package(package_name, expected_hash):
    url = f"https://pypi.org/packages/source/{package_name[0]}/{package_name}/{package_name}.tar.gz"

    response = requests.get(url, stream=True)

    if response.status_code == 200:
        sha256_hash = hashlib.sha256()
        for chunk in response.iter_content(chunk_size=8192):
            sha256_hash.update(chunk)

        if sha256_hash.hexdigest() == expected_hash:
            with open(f"{package_name}.tar.gz", "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                  f.write(chunk)
            print(f"{package_name} downloaded and verified successfully.")
        else:
            print("Integrity check failed: The package may have been tampered with.")
    else:
        print("Failed to download the package.")

download_package('requests', 'a538b17c8e9f00f7060873717554b4c9a1e0171b4c8f378030e3c0a34a36f1f7')