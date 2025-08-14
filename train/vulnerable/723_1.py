import os

def download_file(url, destination):
    os.system(f"curl -k -o {destination} {url}")

download_file('https://example.com/deployUtil.py', 'deployUtil.py')
download_file('https://example.com/vds_bootstrap.py', 'vds_bootstrap.py')