import requests
import os
import tarfile
import time
import json
import ast
import sys
import pkgutil
import re

# Set of built-in modules in Python
builtin_modules = {name for _, name, is_pkg in pkgutil.iter_modules() if not is_pkg}
builtin_modules.update(sys.builtin_module_names)

# Track downloaded packages to avoid duplicate work
downloaded_packages = set()

def extract_package_name(package_string):
    """Extract base package name from a string that might include version constraints."""
    # Match package name (stops at version specifiers or whitespace)
    match = re.match(r'^([a-zA-Z0-9_\-\.]+)', package_string)
    if match:
        return match.group(1)
    return package_string  # Return original if no match

def separate_package_and_version(package_string):
    """
    Separate a package string into its name and version constraint.
    
    Args:
        package_string: String like 'package==1.0.0', 'package>=2.0', 'package=1.0', etc.
        
    Returns:
        Tuple of (package_name, version_constraint) where version_constraint 
        includes the operator (==, >=, etc.) or None if no version specified.
    """
    # First try standard format with operators (==, >=, etc.)
    match = re.match(r'^([a-zA-Z0-9_\-\.]+)(?:([<>=~!]+.+))?$', package_string.strip())
    if match:
        package_name, version_constraint = match.groups()
        if version_constraint:
            return package_name, version_constraint
            
    # Try non-standard format with single equals
    match = re.match(r'^([a-zA-Z0-9_\-\.]+)=([^=].+)$', package_string.strip())
    if match:
        package_name, version = match.groups()
        # Convert to standard format
        return package_name, f"=={version}"
        
    # Return default if no match
    return package_string, None

def is_package_on_pypi(package_string):
    """
    Check if package is available on PyPI, considering version constraints.
    
    Args:
        package_string: Package name with optional version specifier
    
    Returns:
        True if package (and version if specified) exists on PyPI
    """
    try:
        package_name, version = separate_package_and_version(package_string)
        
        # If version specified, check that specific version
        if version:
            # Strip operators and get just the version number
            version_num = version.lstrip('=<>~!')
            url = f"https://pypi.org/pypi/{package_name}/{version_num}/json"
        else:
            url = f"https://pypi.org/pypi/{package_name}/json"
            
        response = requests.get(url)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def dl_packages(packages, target_directory):
    successful_downloads = 0
    failed_packages = []
    total_packages = len(packages)
    
    for index, package_string in enumerate(packages, start=1):
        package_name, version = separate_package_and_version(package_string)
        package_dir = os.path.join(target_directory, package_name)
        os.makedirs(package_dir, exist_ok=True)
        retries = 3
        delay = 1
        success = False
        
        while retries > 0 and not success:
            try:
                # Use version in API call if specified
                if version:
                    # Strip operators and get just the version number
                    version_num = version.lstrip('=<>~!')
                    r = requests.get(f"https://pypi.org/pypi/{package_name}/{version_num}/json")
                else:
                    r = requests.get(f"https://pypi.org/pypi/{package_name}/json")
                    
                r.raise_for_status()
                d = r.json()
                for url in d["urls"]:
                    if url["packagetype"] == "sdist":
                        download_url = url["url"]
                        print(f"Downloading {package_name} ({version or 'latest'}) from {download_url}")
                        response = requests.get(download_url)
                        response.raise_for_status()
                        file_name = os.path.basename(download_url)
                        with open(os.path.join(package_dir, file_name), 'wb') as file:
                            file.write(response.content)
                        print(f"Downloaded {package_name} ({version or 'latest'}) into {package_dir}/{file_name}")
                        successful_downloads += 1
                        success = True
                        break
                if not success:
                    raise Exception("No sdist found in package metadata")
            except requests.exceptions.RequestException as req_e:
                print(f"Failed to download {package_string}: HTTP request error - {req_e}")
                retries -= 1
            except json.JSONDecodeError as json_e:
                print(f"Failed to download {package_string}: JSON decoding error - {json_e}")
                retries -= 1
            except Exception as e:
                print(f"Failed to download {package_string}: {e}")
                retries -= 1

            if retries > 0 and not success:
                print(f"Retrying in {delay} seconds...")
                time.sleep(delay)
                delay *= 2  # Exponential backoff
            elif retries == 0:
                print(f"Max retries reached for {package_string}. Skipping.")
                failed_packages.append(package_string)
        
        # Mark package name (without version) as processed
        downloaded_packages.add(package_name)
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
    
    for package_string in packages:
        package_name, version = separate_package_and_version(package_string)
        
        if package_name in downloaded_packages or package_name in builtin_modules:
            continue  # Skip already downloaded or built-in modules
        
        if not is_package_on_pypi(package_string):
            print(f"Package {package_string} not found on PyPI. Skipping.")
            downloaded_packages.add(package_name)
            continue
        
        dl_packages([package_string], target_directory)
        package_dir = os.path.join(target_directory, package_name)
        
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
                    print(f"Imports found in {package_name}: {new_imports}")
                    
                    # Recursively parse new imports with increased depth
                    download_and_parse_recursively(new_imports - downloaded_packages, target_directory, current_depth + 1, max_depth)
            except (tarfile.ReadError, tarfile.CompressionError) as e:
                print(f"Failed to extract {tar_file}: {e}")

# Initial call with version specification example
test_packages = ['django==4.2.0']  # Specify version
download_directory = './packages/'
download_and_parse_recursively(test_packages, download_directory, max_depth=4)

print("Recursive download and parsing process completed.")