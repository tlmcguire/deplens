# docker build -t dep-tree .
# docker run --rm -v "$(pwd)/graphs:/graphs" dep-tree

import subprocess
import sys
import os
import json

def install_package(package_name):
    """Install a package using pip."""
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--root-user-action=ignore', package_name])
        print(f"Successfully installed {package_name}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install {package_name}: {e}")

def run_pipdeptree(package_name):
    # Use the absolute path for the output directory
    output_dir = '/graphs'
    os.makedirs(output_dir, exist_ok=True)

    # Construct the command to generate a Graphviz output
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

# Example usage
if __name__ == "__main__":
    package = 'flask'  # Replace with the desired package name
    install_package(package)
    run_pipdeptree(package)