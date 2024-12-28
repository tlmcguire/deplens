# docker build -t deplens .
# docker run --rm -it -v "$(pwd)/graphs:/graphs" deplens

import subprocess
import sys
import os
import json
import requests
import tarfile
import ast
import importlib

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

    png_file = os.path.join(output_dir, f"{package_name}_dependency_tree.png")
    json_file = os.path.join(output_dir, f"{package_name}_dependency_tree.json")

    subprocess.run(['pipdeptree', '-p', package_name, '--graph-output', 'png'], stdout=open(png_file, 'wb'))
    result = subprocess.run(['pipdeptree', '-p', package_name, '--json-tree'], stdout=subprocess.PIPE)
    with open(json_file, 'w') as f:
        json.dump(json.loads(result.stdout.decode('utf-8')), f, indent=4)

    print(f"Dependency tree saved as {png_file} and {json_file}")

def parse_json_for_packages(json_file):
    """Extract package names from pipdeptree JSON."""
    with open(json_file) as f:
        data = json.load(f)
    
    packages = set()

    def traverse(node):
        if "package_name" in node:
            packages.add(node["package_name"])
        for child in node.get("dependencies", []):
            traverse(child)

    for node in data:
        traverse(node)
    
    return packages

def download_and_extract_packages(package_names, download_dir):
    """Download and extract source packages from PyPI."""
    os.makedirs(download_dir, exist_ok=True)

    for package in package_names:
        try:
            print(f"Downloading {package} from PyPI...")
            response = requests.get(f"https://pypi.org/pypi/{package}/json")
            urls = response.json().get('urls', [])

            for url in urls:
                if url['packagetype'] == 'sdist':
                    tarball_url = url['url']
                    tarball_response = requests.get(tarball_url)
                    tarball_filename = os.path.basename(tarball_url)
                    tarball_path = os.path.join(download_dir, tarball_filename)

                    with open(tarball_path, 'wb') as file:
                        file.write(tarball_response.content)

                    print(f"Extracting {tarball_path}...")
                    with tarfile.open(tarball_path, 'r:gz') as tar:
                        tar.extractall(path=download_dir)

                    # Rename the extracted directory
                    extracted_dir = tarball_filename.replace('.tar.gz', '')
                    src_dir = os.path.join(download_dir, extracted_dir)
                    dst_dir = os.path.join(download_dir, package)
                    if os.path.exists(src_dir):
                        os.rename(src_dir, dst_dir)
        except Exception as e:
            print(f"Failed to download {package}: {e}")

def search_function_definitions(root_dir, function_name):
    """Search for a specific function definition in all Python files."""
    for subdir, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(subdir, file)
                with open(file_path, 'r') as f:
                    tree = ast.parse(f.read())
                    for node in ast.walk(tree):
                        if isinstance(node, ast.FunctionDef) and node.name == function_name:
                            print(f"Found '{function_name}' in {file_path}")
                            return file_path, node

class FunctionRenamer(ast.NodeTransformer):
    def __init__(self, target_name, new_name):
        self.target_name = target_name
        self.new_name = new_name

    def visit_FunctionDef(self, node):
        if node.name == self.target_name:
            print(f"Renaming function '{node.name}' to '{self.new_name}'")
            node.name = self.new_name
        self.generic_visit(node)
        return node

def modify_function_ast(file_path, target_name, new_name):
    """Modify the function's name in the AST and rewrite the file."""
    with open(file_path, 'r') as f:
        tree = ast.parse(f.read())

    renamer = FunctionRenamer(target_name, new_name)
    new_tree = renamer.visit(tree)

    new_code = ast.unparse(new_tree)

    with open(file_path, 'w') as f:
        f.write(new_code)

    print(f"Modified {file_path} and renamed function to '{new_name}'")

def load_local_packages(packages_dir):
    """Dynamically load modified packages."""
    sys.path.insert(0, packages_dir)
    for package_name in os.listdir(packages_dir):
        package_path = os.path.join(packages_dir, package_name)
        if os.path.isdir(package_path):
            try:
                importlib.import_module(package_name)
                print(f"Loaded {package_name}")
            except Exception as e:
                print(f"Error loading {package_name}: {e}")

def visualize_ast(file_paths):
    """Visualize the AST of the specified Python files using astvisualizer.py."""
    for file_path in file_paths:
        subprocess.run(['python', 'astvisualizer.py', '-f', file_path])

if __name__ == "__main__":
    package = 'flask'  # Change this to the desired package
    install_package(package)
    run_pipdeptree(package)

    packages_dir = '/packages'
    download_dir = packages_dir

    json_file = f'/graphs/{package}_dependency_tree.json'
    package_names = parse_json_for_packages(json_file)

    download_and_extract_packages(package_names, download_dir)

    # Print the packages found
    print("Packages found:")
    packages_list = [pkg for pkg in os.listdir(download_dir) if not pkg.endswith('.tar.gz')]
    for i, pkg in enumerate(packages_list):
        print(f"{i + 1}. {pkg}")

    # Prompt the user to select a package
    selected_package_index = int(input("Enter the number of the package to visualize: ")) - 1
    selected_package = packages_list[selected_package_index]

    # Print the Python files found in the selected package
    selected_package_dir = os.path.join(download_dir, selected_package)
    python_files = []
    for subdir, _, files in os.walk(selected_package_dir):
        for file in files:
            if file.endswith(".py"):
                python_files.append(os.path.join(subdir, file))

    print("Python files found:")
    for i, file in enumerate(python_files):
        print(f"{i + 1}. {file}")

    # Prompt the user to select files to visualize
    selected_files = input("Enter the numbers of the files to visualize (comma-separated): ")
    selected_files = [python_files[int(i) - 1] for i in selected_files.split(",")]

    visualize_ast(selected_files)

    function_name = 'visit_ScopedEvalContextModifier'  # Function to search for
    new_function_name = 'modified_visit_ScopedEvalContextModifier'  # New function name

    for pkg in os.listdir(download_dir):
        pkg_path = os.path.join(download_dir, pkg)
        package_name = os.path.basename(pkg_path).split('-')[0]
        result = search_function_definitions(pkg_path, function_name)
        if result:
            file_path, node = result
            modify_function_ast(file_path, function_name, new_function_name)
            break

    load_local_packages(download_dir)
    print("Ready to test with modified dependencies.")
    # Import the main package to test
    module = importlib.import_module(package)