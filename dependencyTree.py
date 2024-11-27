# docker build -t dep-tree .
# docker run --rm -v "$(pwd)/graphs:/graphs" dep-tree

import subprocess
import sys
import os
import json
import requests
import time
import tarfile

def install_package(package_name):
    """Install a package using pip."""
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--root-user-action=ignore', package_name])
        print(f"Successfully installed {package_name}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install {package_name}: {e}")

def run_pipdeptree(package_name):
    """Run pipdeptree to generate the dependency tree as a PNG and JSON."""
    output_dir = '/graphs'
    os.makedirs(output_dir, exist_ok=True)

    png_command = ['pipdeptree', '-p', package_name, '--graph-output', 'png']
    json_command = ['pipdeptree', '-p', package_name, '--json-tree']

    try:
        # Generate PNG file for the dependency tree
        png_output_file = os.path.join(output_dir, f"{package_name}_dependency_tree.png")
        with open(png_output_file, 'wb') as f:
            subprocess.run(png_command, stdout=f, stderr=subprocess.PIPE, check=True)
        
        print(f"Dependency tree saved as {png_output_file}")

        # Generate JSON file for the dependency tree
        json_output_file = os.path.join(output_dir, f"{package_name}_dependency_tree.json")
        with open(json_output_file, 'w', encoding='utf-8') as f:
            result = subprocess.run(json_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            json_data = result.stdout.decode('utf-8')
            json.dump(json.loads(json_data), f, ensure_ascii=False, indent=4)
        
        print(f"Dependency tree saved as {json_output_file}")

    except subprocess.CalledProcessError as e:
        print(f"Error executing pipdeptree: {e.stderr.decode('utf-8')}")

def parse_json_for_packages(json_file):
    """Parse the JSON file and return a set of package names including dependencies."""
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        packages = set()
        
        def traverse(node):
            package_name = node.get('package_name')
            if package_name:
                packages.add(package_name)
            else:
                print(f"Missing 'package_name' in node: {node}")
            for child in node.get('dependencies', []):
                traverse(child)
        
        for node in data:
            traverse(node)
        
        return packages
        
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error reading JSON file: {e}")
        return set()

def download_package(package, package_dir, retries=3, delay=1):
    """Download a package from PyPI given its name."""
    success = False
    while retries > 0 and not success:
        try:
            # Fetch package information from PyPI
            r = requests.get(f"https://pypi.org/pypi/{package}/json")
            r.raise_for_status()  # Check if the request was successful
            d = r.json()

            # Look for the first sdist package
            for url in d["urls"]:
                if url["packagetype"] == "sdist":
                    download_url = url["url"]
                    print(f"Downloading {package} from {download_url}")
                    response = requests.get(download_url)
                    response.raise_for_status()  # Ensure successful download

                    # Save the downloaded file
                    file_name = os.path.basename(download_url)
                    os.makedirs(package_dir, exist_ok=True)
                    with open(os.path.join(package_dir, file_name), 'wb') as file:
                        file.write(response.content)

                    print(f"Downloaded {package} into {package_dir}/{file_name}")
                    success = True
                    break
            if not success:
                print(f"No sdist found for {package}, retrying...")
                retries -= 1
                time.sleep(delay)
        except requests.exceptions.RequestException as e:
            print(f"Error downloading {package}: {e}")
            retries -= 1
            time.sleep(delay)
    
    if not success:
        print(f"Failed to download {package} after {3 - retries} retries.")

def download_packages_from_json(json_file, download_dir):
    """Download all packages from the JSON dependency tree."""
    package_names = parse_json_for_packages(json_file)

    # Download each package
    successful_downloads = 0
    for package in package_names:
        print(f"Attempting to download package: {package}")
        download_package(package, download_dir)
        successful_downloads += 1

    print(f"Successfully downloaded {successful_downloads}/{len(package_names)} packages.")

def extract_packages(package_dir):
    """Extract all .tar.gz files in the specified directory."""
    for filename in os.listdir(package_dir):
        if filename.endswith('.tar.gz'):
            file_path = os.path.join(package_dir, filename)
            try:
                with tarfile.open(file_path, 'r:gz') as tar:
                    tar.extractall(path=package_dir)
                print(f"Extracted {filename}")
            except tarfile.TarError as e:
                print(f"Error extracting {filename}: {e}")

# Example usage
if __name__ == "__main__":
    package = 'flask'  # Replace with the desired package name
    install_package(package)
    run_pipdeptree(package)
    
    # Path where packages will be downloaded
    download_dir = '/packages'

    # After running pipdeptree and saving the JSON, call the download function
    json_file = f'/graphs/{package}_dependency_tree.json'
    download_packages_from_json(json_file, download_dir)

    # Extract the downloaded packages
    extract_packages(download_dir)