import requests
import os
import tarfile
import time
import json
import ast
import sys
import pkgutil

# Set of built-in modules in Python
builtin_modules = {name for _, name, is_pkg in pkgutil.iter_modules() if not is_pkg}
builtin_modules.update(sys.builtin_module_names)

# Track downloaded packages to avoid duplicate work
downloaded_packages = set()

def is_package_on_pypi(package_name):
    try:
        response = requests.get(f"https://pypi.org/pypi/{package_name}/json")
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def dl_packages(packages, target_directory):
    successful_downloads = 0
    failed_packages = []
    total_packages = len(packages)
    
    for index, package in enumerate(packages, start=1):
        package_dir = os.path.join(target_directory, package)
        os.makedirs(package_dir, exist_ok=True)
        retries = 3
        delay = 1
        success = False
        
        while retries > 0 and not success:
            try:
                r = requests.get(f"https://pypi.org/pypi/{package}/json")
                r.raise_for_status()
                d = r.json()
                for url in d["urls"]:
                    if url["packagetype"] == "sdist":
                        download_url = url["url"]
                        print(f"Downloading {package} from {download_url}")
                        response = requests.get(download_url)
                        response.raise_for_status()
                        file_name = os.path.basename(download_url)
                        with open(os.path.join(package_dir, file_name), 'wb') as file:
                            file.write(response.content)
                        print(f"Downloaded {package} into {package_dir}/{file_name}")
                        successful_downloads += 1
                        success = True
                        break
                if not success:
                    raise Exception("No sdist found in package metadata")
            except requests.exceptions.RequestException as req_e:
                print(f"Failed to download {package}: HTTP request error - {req_e}")
                retries -= 1
            except json.JSONDecodeError as json_e:
                print(f"Failed to download {package}: JSON decoding error - {json_e}")
                retries -= 1
            except Exception as e:
                print(f"Failed to download {package}: {e}")
                retries -= 1

            if retries > 0 and not success:
                print(f"Retrying in {delay} seconds...")
                time.sleep(delay)
                delay *= 2  # Exponential backoff
            elif retries == 0:
                print(f"Max retries reached for {package}. Skipping.")
                failed_packages.append(package)
        
        downloaded_packages.add(package)  # Mark as processed
        print(f"Progress: {index}/{total_packages} packages processed")
    
    print(f"\nDownload complete. {successful_downloads} packages downloaded successfully.")
    if failed_packages:
        print(f"{len(failed_packages)} packages failed to download: {failed_packages}")

def parse_imports(directory):
    imports = set()
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        try:
                            tree = ast.parse(f.read(), filename=file_path)
                            for node in ast.walk(tree):
                                if isinstance(node, ast.Import):
                                    for alias in node.names:
                                        imports.add(alias.name.split('.')[0])  # Cutoff submodule, get top-level package
                                elif isinstance(node, ast.ImportFrom):
                                    if node.module:
                                        imports.add(node.module.split('.')[0])  # Cutoff submodule, get top-level package
                        except (SyntaxError, UnicodeDecodeError) as e:
                            print(f"Error parsing {file_path}: {e}")
                except (UnicodeDecodeError, FileNotFoundError) as e:
                    print(f"Skipping {file_path} due to encoding issues or file not found: {e}")
    return imports

def download_and_parse_recursively(packages, target_directory, current_depth=0, max_depth=3):
    """Recursively download and parse packages with a depth limit."""
    if not packages or current_depth > max_depth:
        return
    
    for package in packages:
        if package in downloaded_packages or package in builtin_modules:
            continue  # Skip already downloaded or built-in modules
        
        if not is_package_on_pypi(package):
            print(f"Package {package} not found on PyPI. Skipping.")
            downloaded_packages.add(package)
            continue
        
        dl_packages([package], target_directory)
        package_dir = os.path.join(target_directory, package)
        
        # Find all tar.gz files in the package directory and extract them
        tar_files = []
        for root, dirs, files in os.walk(package_dir):
            for file in files:
                if file.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
                    tar_files.append(os.path.join(root, file))

        for tar_file in tar_files:
            try:
                if tar_file.endswith(".tar.gz"):
                    mode = 'r:gz'
                elif tar_file.endswith(".tar.bz2"):
                    mode = 'r:bz2'
                elif tar_file.endswith(".tar.xz"):
                    mode = 'r:xz'
                else:
                    mode = 'r'
                
                with tarfile.open(tar_file, mode) as tar_ref:
                    extract_dir = os.path.splitext(os.path.splitext(tar_file)[0])[0]
                    tar_ref.extractall(extract_dir)
                    print(f"Extracted {tar_file} to {extract_dir}")
                    
                    new_imports = parse_imports(extract_dir)
                    print(f"Imports found in {package}: {new_imports}")
                    
                    # Recursively parse new imports with increased depth
                    download_and_parse_recursively(new_imports - downloaded_packages, target_directory, current_depth + 1, max_depth)
            except (tarfile.ReadError, tarfile.CompressionError) as e:
                print(f"Failed to extract {tar_file}: {e}")

# Initial call
test_packages = ['flask']
download_directory = './packages/'
download_and_parse_recursively(test_packages, download_directory, max_depth=4)

print("Recursive download and parsing process completed.")