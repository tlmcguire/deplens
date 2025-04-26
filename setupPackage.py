#!/usr/bin/env python3
"""
Script to download and extract package source code for testing.
This allows you to install packages, modify them, and then analyze them with interactiveGraph.py.

Usage: python setup_package.py package_name[==version]
Example: python setup_package.py django==4.2.0
"""

# ==============================================================================
# Workflow for Package Testing and Vulnerability Analysis
# ==============================================================================
# 1. Start Docker container in interactive mode:
#    docker run --rm -it -p 8080:8080 --add-host=host.docker.internal:host-gateway \
#      -v "$(pwd)/graphs:/graphs" -v "$(pwd)/models:/models" \
#      -v "$(pwd)/results:/app/results" deplens /bin/bash
#
# 2. Download and extract a package (this script):
#    python setupPackage.py <package_name>==<version>
#
# 3. Modify the package source code as needed
#
# 4. Run analysis with interactiveGraph.py:
#    python interactiveGraph.py --skip-download <package_name>==<version>
#
# 5. Access the dashboard:
#    http://localhost:8080
# ==============================================================================

import sys
import os
import re
import json
import shutil
import tarfile
import importlib
import subprocess
import requests

def extract_package_name(package_string):
    """Extract base package name from a string that might include version constraints."""
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

def is_package_installed(package_name):
    """Check if package is already installed."""
    try:
        # Extract base name for importlib
        base_name = extract_package_name(package_name)
        importlib.import_module(base_name)
        return True
    except ImportError:
        return False

def install_package(package_name):
    """Install a package using pip."""
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--root-user-action=ignore', package_name])
        print(f"Successfully installed {package_name}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install {package_name}: {e}")

def run_pipdeptree(package_name):
    """Generate dependency tree as PNG and JSON using pipdeptree."""
    output_dir = '/graphs'
    os.makedirs(output_dir, exist_ok=True)
    
    # Extract base name for file paths
    base_name = extract_package_name(package_name)
    
    png_file = os.path.join(output_dir, f"{base_name}_dependency_tree.png")
    json_file = os.path.join(output_dir, f"{base_name}_dependency_tree.json")

    try:
        # Use base name for pipdeptree
        subprocess.run(['pipdeptree', '-p', base_name, '--graph-output', 'png'], 
                      stdout=open(png_file, 'wb'), check=True)
        result = subprocess.run(['pipdeptree', '-p', base_name, '--json-tree'], 
                              stdout=subprocess.PIPE, check=True)
        
        # Verify JSON output is valid
        try:
            json_data = json.loads(result.stdout.decode('utf-8'))
            with open(json_file, 'w') as f:
                json.dump(json_data, f, indent=4)
        except json.JSONDecodeError:
            print(f"Invalid JSON output for {base_name}")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"Failed to generate dependency tree: {e}")
        return False
    
    return True

def clean_package_directory(package_name):
    """Clean up package directory before extraction."""
    # Make sure we're using base name
    base_name = extract_package_name(package_name)
    package_path = f'/packages/{base_name}'
    try:
        if os.path.exists(package_path):
            print(f"Removing existing directory: {package_path}")
            shutil.rmtree(package_path)
    except Exception as e:
        print(f"Error cleaning directory for {base_name}: {e}")

def get_json_filepath(package_name):
    """Get the filepath for a package's JSON dependency tree."""
    # Extract base name for file paths
    base_name = extract_package_name(package_name)
    return f"/graphs/{base_name}_dependency_tree.json"

def download_and_extract_packages(package_names, download_dir):
    """Download and extract source packages from PyPI."""
    print(f"Creating download directory: {download_dir}")  
    os.makedirs(download_dir, exist_ok=True)

    # Extract the original version from package variable
    pkg_name = list(package_names)[0]  # Get the first package from set
    original_name, original_version = separate_package_and_version(pkg_name)
    print(f"Original package request: {pkg_name} (name: {original_name}, version: {original_version})")

    # Generate the dependency tree if needed
    if not os.path.exists(get_json_filepath(pkg_name)):
        if not is_package_installed(pkg_name):
            install_package(pkg_name)
        run_pipdeptree(pkg_name)

    # Load main package JSON
    filepath = get_json_filepath(pkg_name)
    try:
        with open(filepath, "r") as f:
            dependency_tree = json.load(f)
            print(f"Loaded dependency tree from: {filepath}")  
    except FileNotFoundError:
        print(f"JSON file not found: {filepath}")
        return None

    def update_package_paths(packages):
        for pkg in packages:
            try:
                package_name = pkg['package_name']
                base_name, version = separate_package_and_version(package_name)
                
                # Apply original version to the main package if it matches
                if base_name.lower() == original_name.lower() and original_version:
                    version = original_version
                    print(f"Applying original version constraint: {version} to {base_name}")
                    
                print(f"Processing package: {package_name} (base name: {base_name}, version: {version})")  
                
                # Use version if specified in the PyPI API call
                if version:
                    api_url = f"https://pypi.org/pypi/{base_name}/{version.lstrip('=<>~!')}/json"
                else:
                    api_url = f"https://pypi.org/pypi/{base_name}/json"
                
                print(f"PyPI API URL: {api_url}")
                
                response = requests.get(api_url)
                if response.status_code != 200:
                    print(f"PyPI API error for {base_name}: {response.status_code}")
                    continue
                    
                urls = response.json().get('urls', [])
                
                if not urls:
                    print(f"No download URLs found for {base_name} (version: {version})")  
                    continue

                for url in urls:
                    if (url['packagetype'] == 'sdist'):
                        tarball_url = url['url']
                        tarball_filename = os.path.basename(tarball_url)
                        tarball_path = os.path.join(download_dir, tarball_filename)
                        package_dir = os.path.join(download_dir, base_name)

                        # Add paths to package data
                        pkg['source_paths'] = {
                            'tarball_path': tarball_path,
                            'package_dir': package_dir
                        }
                        
                        print(f"Using package dir: {package_dir}")

                        with open(tarball_path, 'wb') as f:
                            response = requests.get(tarball_url)
                            f.write(response.content)

                        print(f"Cleaning directory: {package_dir}")  
                        clean_package_directory(base_name)
                        
                        print(f"Extracting {tarball_filename}")  
                        with tarfile.open(tarball_path, 'r:gz') as tar:
                            tar.extractall(path=download_dir)

                        # Rename extracted directory
                        extracted_dir = tarball_filename.replace('.tar.gz', '')
                        src_dir = os.path.join(download_dir, extracted_dir)
                        if os.path.exists(src_dir):
                            print(f"Renaming {src_dir} to {package_dir}")  
                            # If target already exists, remove it first
                            if os.path.exists(package_dir):
                                shutil.rmtree(package_dir)
                            os.rename(src_dir, package_dir)
                        else:
                            print(f"Source directory not found: {src_dir}")  
                        
                        break

                # Process dependencies recursively
                if pkg.get('dependencies'):
                    update_package_paths(pkg['dependencies'])

            except Exception as e:
                print(f"Error processing {package_name}: {str(e)}")
                import traceback
                traceback.print_exc()

    # Update paths and save
    update_package_paths(dependency_tree)
    
    print(f"Saving updated dependency tree to: {filepath}")  
    with open(filepath, "w") as f:
        json.dump(dependency_tree, f, indent=2)

    return dependency_tree

def main():
    if len(sys.argv) < 2:
        print("Usage: python setup_package.py package_name[==version]")
        print("Example: python setup_package.py django==4.2.0")
        sys.exit(1)
    
    package_name = sys.argv[1]
    print(f"Setting up package: {package_name}")
    
    # Ensure packages directory exists
    os.makedirs('/packages', exist_ok=True)
    
    # Install package if needed
    if not is_package_installed(package_name):
        install_package(package_name)
    
    # Generate dependency tree
    run_pipdeptree(package_name)
    
    # Download and extract package source
    download_and_extract_packages(set([package_name]), '/packages')
    
    base_name = extract_package_name(package_name)
    package_dir = f'/packages/{base_name}'
    
    print(f"\nSetup completed successfully!")
    print(f"Package source code is available at: {package_dir}")
    print(f"After making changes, run: python interactiveGraph.py --skip-download {package_name}")

if __name__ == "__main__":
    main()