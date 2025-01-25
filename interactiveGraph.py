# docker build -t deplens .
# docker run --rm -it -p 8080:8080 -v "$(pwd)/graphs:/graphs" deplens

from dash import Dash, html, dcc
import dash_cytoscape as cyto
from dash.dependencies import Input, Output
import json
import os
import subprocess
import sys
import requests
import tarfile
import ast
import importlib
import shutil

package = 'flask' # Change this to the desired package
file = f"/graphs/{package}_dependency_tree.json" # Load the JSON dependency tree

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

def clean_package_directory(package_name):
    """Clean up package directory before extraction."""
    package_path = f'/packages/{package_name}'
    try:
        if os.path.exists(package_path):
            shutil.rmtree(package_path)
    except Exception as e:
        print(f"Error cleaning directory for {package_name}: {e}")

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
                    clean_package_directory(package)
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

def get_data():
    """Load the dependency tree data from a JSON file."""
    with open(file, "r") as json_file:
        data = json.load(json_file)
        return data

def def_elems(pkg_data, parent=None, vulnerable_packages=[]):
    """
    Recursively map package data into Cytoscape elements.

    :param pkg_data: The package data dictionary.
    :param parent: The parent node ID, if any.
    :param vulnerable_packages: List of package names marked as vulnerable.
    :return: List of Cytoscape elements.
    """
    elements = []
    node_id = pkg_data["package_name"]
    label = f"{node_id}\nv{pkg_data['installed_version']}"
    color = "#FF0000" if node_id in vulnerable_packages else "#018786"  # Red for vulnerable, default for safe
    
    # Add the current node
    elements.append({'data': {'id': node_id, 'label': label}, 'style': {'background-color': color}})
    
    # Add an edge if there's a parent
    if parent:
        elements.append({'data': {'source': parent, 'target': node_id}})
    
    # Process dependencies recursively
    for dep in pkg_data.get("dependencies", []):
        elements += def_elems(dep, parent=node_id, vulnerable_packages=vulnerable_packages)
    
    return elements

# Vulnerable packages list (hardcoded for now, could be fetched dynamically)
vulnerable_packages = ["werkzeug", "click"]

# Load dependency data and generate elements
dep_data = get_data()
elements = def_elems(dep_data[0], vulnerable_packages=vulnerable_packages)

# Dash app setup
app = Dash(__name__)

app.layout = html.Div([
    html.Div([
        html.H1("DepLens", style={'text-align': 'left', 'color': 'white'}),
        html.Div(id='output-div', style={'padding': '2px', 'color': 'white'})
    ], style={'background-color': '#222222', 'padding': '3px'}),
    cyto.Cytoscape(
        id='cytoscape',
        layout={'name': 'breadthfirst'},
        style={'width': '100%', 'height': '80vh', 'background-color': '#222222'},
        elements=elements,
        stylesheet=[
            {'selector': 'node', 
             'style': {
                 'content': 'data(label)', 
                 'color': 'white', 
                 'text-wrap': 'wrap', 
                 'text-valign': 'center', 
                 'text-halign': 'center',
                 'shape': 'round-rectangle',
                 'width': '100px',
                 'height': '50px',
                 'background-color': '#333333',
                 'border-width': '2px',
                 'border-color': '#333333',
                 'border-radius': '5%',
                 'padding': '2px'
             }},
            {'selector': 'edge', 
             'style': {
                 'line-color': '#00FFFF',  # teal
                 'width': 2,
                 'curve-style': 'bezier',
                 'target-arrow-color': '#00FFFF',  # teal
                 'target-arrow-shape': 'triangle',
                 'arrow-scale': 2,
                 'target-arrow-fill': 'filled'
             }}
        ]
    )
])

# Callback to display information on node click
@app.callback(
    Output('output-div', 'children'),
    [Input('cytoscape', 'tapNodeData')]
)
def display_click_data(data):
    if data:
        return f"Package: {data['label']}"
    return "Click a node to see details."


if __name__ == "__main__":
    install_package(package)
    run_pipdeptree(package)

    packages_dir = '/packages'
    download_dir = packages_dir

    json_file = f'/graphs/{package}_dependency_tree.json'
    package_names = parse_json_for_packages(json_file)

    download_and_extract_packages(package_names, download_dir)

    # Ensure the graphs directory exists
    os.makedirs("graphs", exist_ok=True)
    
    app.run(debug=True, host='0.0.0.0', port=8080)