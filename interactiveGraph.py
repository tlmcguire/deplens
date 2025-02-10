"""
Interactive dependency graph visualization using Dash and Cytoscape.
Analyzes Python package dependencies and displays them in an interactive web interface.

Build: docker build -t deplens .
Run: docker run --rm -it -p 8080:8080 -v "$(pwd)/graphs:/graphs" deplens

"""

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

# Dictionary for web interface theme colors
THEME = {
    'text': '#E0E0E0',  # Light gray
    'highlight': '#4FC3F7',  # Light blue
    'secondary': '#B0BEC5',  # Blue gray
    'background': '#333333'  # Dark gray
}

# Global variables
initialized = False
package = 'flask'
elements = []  # Default empty list
vulnerable_packages = ["Werkzeug", "click"]

def is_package_installed(package_name):
    """Check if package is already installed."""
    try:
        importlib.import_module(package_name)
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

    png_file = os.path.join(output_dir, f"{package_name}_dependency_tree.png")
    json_file = os.path.join(output_dir, f"{package_name}_dependency_tree.json")

    try:
        subprocess.run(['pipdeptree', '-p', package_name, '--graph-output', 'png'], 
                      stdout=open(png_file, 'wb'), check=True)
        result = subprocess.run(['pipdeptree', '-p', package_name, '--json-tree'], 
                              stdout=subprocess.PIPE, check=True)
        
        # Verify JSON output is valid
        try:
            json_data = json.loads(result.stdout.decode('utf-8'))
            with open(json_file, 'w') as f:
                json.dump(json_data, f, indent=4)
        except json.JSONDecodeError:
            print(f"Invalid JSON output for {package_name}")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"Failed to generate dependency tree: {e}")
        return False
    
    return True

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

def get_json_filepath(package_name):
    """Get the filepath for a package's JSON dependency tree."""
    return f"/graphs/{package_name}_dependency_tree.json"

def get_data(package_name):
    """Load or create the dependency tree data from a JSON file."""
    filepath = get_json_filepath(package_name)
    
    # Create JSON if it doesn't exist
    if not os.path.exists(filepath):
        if not is_package_installed(package_name):
            install_package(package_name)
        run_pipdeptree(package_name)
    
    # Load and return JSON data
    with open(filepath, "r") as json_file:
        data = json.load(json_file)
        return data

def download_and_extract_packages(package_names, download_dir):
    """Download and extract source packages from PyPI."""
    os.makedirs(download_dir, exist_ok=True)

    # Load main package JSON
    filepath = get_json_filepath(package)
    try:
        with open(filepath, "r") as f:
            dependency_tree = json.load(f)
    except FileNotFoundError:
        print(f"JSON file not found: {filepath}")
        return None

    def update_package_paths(packages):
        for pkg in packages:
            try:
                print(f"Downloading {pkg['package_name']} from PyPI...")
                response = requests.get(f"https://pypi.org/pypi/{pkg['package_name']}/json")
                urls = response.json().get('urls', [])

                for url in urls:
                    if url['packagetype'] == 'sdist':
                        tarball_url = url['url']
                        tarball_response = requests.get(tarball_url)
                        tarball_filename = os.path.basename(tarball_url)
                        tarball_path = os.path.join(download_dir, tarball_filename)

                        # Add paths to package data
                        pkg['source_paths'] = {
                            'tarball_path': tarball_path,
                            'package_dir': os.path.join(download_dir, pkg['package_name'])
                        }

                        with open(tarball_path, 'wb') as f:
                            f.write(tarball_response.content)

                        print(f"Extracting {tarball_path}...")
                        clean_package_directory(pkg['package_name'])
                        with tarfile.open(tarball_path, 'r:gz') as tar:
                            tar.extractall(path=download_dir)

                        # Rename extracted directory
                        extracted_dir = tarball_filename.replace('.tar.gz', '')
                        src_dir = os.path.join(download_dir, extracted_dir)
                        dst_dir = os.path.join(download_dir, pkg['package_name'])
                        if os.path.exists(src_dir):
                            os.rename(src_dir, dst_dir)
                        
                        break

                # Process dependencies recursively
                if pkg.get('dependencies'):
                    update_package_paths(pkg['dependencies'])

            except Exception as e:
                print(f"Failed to download {pkg['package_name']}: {e}")

    # Update paths and save
    update_package_paths(dependency_tree)
    with open(filepath, "w") as f:
        json.dump(dependency_tree, f, indent=2)

    return dependency_tree

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

def initialize_data():
    """Initialize data and elements for the graph."""
    global elements
    try:
        dep_data = get_data(package)
        elements = def_elems(dep_data[0], vulnerable_packages=vulnerable_packages)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error initializing data: {e}")
        # Set default elements if initialization fails
        elements = [{'data': {'id': package, 'label': package}}]

def initialize():
    """Initialize the environment once."""
    global initialized
    if initialized:
        return
    
    if not os.path.exists('/packages'):
        download_and_extract_packages(set([package]), '/packages')
    
    initialize_data()
    initialized = True

def fetch_package_metadata(package_name):
    """Fetch additional package metadata from PyPI."""
    try:
        response = requests.get(f"https://pypi.org/pypi/{package_name}/json")
        if response.status_code == 200:
            data = response.json()
            return {
                'name': data['info']['name'],
                'version': data['info']['version'],
                'description': data['info']['summary'],
                'author': data['info']['author'],
                'homepage': data['info']['home_page'],
                'license': data['info']['license']
            }
    except Exception as e:
        print(f"Error fetching metadata for {package_name}: {e}")
        return None

class FileNode:
    def __init__(self, name, path, node_type='file'):
        self.name = name
        self.path = path
        self.type = node_type
        self.children = []
        
    def add_child(self, child):
        self.children.append(child)

def build_file_tree(package_data):
    """Build file tree from package directory."""
    package_dir = package_data.get('source_paths', {}).get('package_dir')
    if not package_dir or not os.path.exists(package_dir):
        return None
        
    root = FileNode(os.path.basename(package_dir), package_dir, 'directory')
    
    def scan_directory(directory, parent_node):
        """Recursively scan directory and create FileNodes for each item."""
        try:
            for item in sorted(os.listdir(directory)):
                full_path = os.path.join(directory, item)
                if os.path.isfile(full_path):
                    node = FileNode(item, full_path)
                    parent_node.add_child(node)
                else:
                    node = FileNode(item, full_path, 'directory')
                    parent_node.add_child(node)
                    scan_directory(full_path, node)
        except Exception as e:
            print(f"Error scanning {directory}: {e}")
            
    scan_directory(package_dir, root)
    return root

def find_package_in_tree(package_name, dependency_tree):
    """Recursively find package data in dependency tree."""
    if dependency_tree['package_name'].lower() == package_name.lower():
        return dependency_tree
        
    for dep in dependency_tree.get('dependencies', []):
        result = find_package_in_tree(package_name, dep)
        if result:
            return result
    return None

def get_file_structure(package_name):
    """Build and render file structure for package."""
    try:
        # Load main package JSON
        with open(get_json_filepath(package)) as f:
            dependency_tree = json.load(f)[0]
        
        # Find package data in dependency tree
        package_data = find_package_in_tree(package_name, dependency_tree)
        if not package_data:
            return html.Div(f"Package {package_name} not found in dependency tree",
                          style={'color': THEME['secondary']})
        
        package_dir = package_data.get('source_paths', {}).get('package_dir')
        if not package_dir or not os.path.exists(package_dir):
            return html.Div(f"No files found for {package_name}",
                          style={'color': THEME['secondary']})
        
        def build_tree(path):
            name = os.path.basename(path)
            if os.path.isfile(path):
                return FileNode(name, path)
            
            node = FileNode(name, path, 'directory')
            try:
                for item in sorted(os.listdir(path)):
                    item_path = os.path.join(path, item)
                    if not item.startswith('.'):  # Skip hidden files
                        child = build_tree(item_path)
                        if child:
                            node.children.append(child)
            except Exception as e:
                print(f"Error scanning {path}: {e}")
            return node
        
        def render_node(node):
            icon = '📁 ' if node.type == 'directory' else '📄 '
            if node.children:
                return html.Details([
                    html.Summary(
                        icon + node.name,
                        style={'color': THEME['highlight'], 'cursor': 'pointer'}
                    ),
                    html.Ul([
                        render_node(child) for child in node.children
                    ], style={'paddingLeft': '20px'})
                ])
            return html.Li(
                icon + node.name,
                style={'color': THEME['text'], 'listStyleType': 'none'}
            )
            
        root = build_tree(package_dir)
        return html.Div([
            html.H3(f"Files for {package_name}",
                   style={'color': THEME['highlight']}),
            render_node(root)
        ])
        
    except Exception as e:
        return html.Div(f"Error loading files: {str(e)}",
                       style={'color': THEME['secondary']})

# Dash app setup
app = Dash(__name__)
initialize()  # Call once at startup

# Update app layout - keep single-content-area ID
app.layout = html.Div([
    html.Div([
        html.H1("DepLens", style={'text-align': 'left', 'color': 'white'}),
        html.Div(id='output-div', style={'padding': '2px', 'color': 'white'})
    ], style={'background-color': '#222222', 'padding': '3px', 'width': '80%'}),
    html.Div([
        html.Div([
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
                         'line-color': '#018786',
                         'width': 2,
                         'curve-style': 'bezier',
                         'target-arrow-color': '#018786',
                         'target-arrow-shape': 'triangle',
                         'arrow-scale': 2,
                         'target-arrow-fill': 'filled'
                     }}
                ]
            )
        ], style={'width': '80%', 'display': 'inline-block', 'vertical-align': 'top'}),
        html.Div([
            html.H3("Package Details", style={'color': 'white'}),
            html.Div(id='package-details', style={'color': 'white'}),
            dcc.Tabs(
                id='info-tabs',
                value='details',
                children=[
                    dcc.Tab(
                        label='Details',
                        value='details',
                        style={'color': THEME['text']},
                        selected_style={'color': THEME['highlight']}
                    ),
                    dcc.Tab(
                        label='Files',
                        value='files',
                        style={'color': THEME['text']},
                        selected_style={'color': THEME['highlight']}
                    )
                ],
                style={'background': THEME['background']}
            ),
            html.Div(
                id='single-content-area',
                style={'color': THEME['text'], 'padding': '15px'}
            )
        ], style={
            'width': '22%',
            'display': 'inline-block',
            'vertical-align': 'top',
            'background': THEME['background'],
            'height': '92.3vh',
            'overflow-y': 'auto',
            'float': 'right',
            'position': 'absolute',  # Add position absolute
            'right': '0',           # Align to right edge
            'top': '0'             # Align to top edge
        })
    ])
])

@app.callback(
    Output('single-content-area', 'children'),
    [Input('info-tabs', 'value'),
     Input('cytoscape', 'tapNodeData')]
)
def update_panel_content(tab, node_data):
    if not node_data:
        return html.Div("Select a package", style={'color': THEME['secondary']})
    
    package_name = node_data['id']
    
    if tab == 'details':
        metadata = fetch_package_metadata(package_name)
        if not metadata:
            return html.Div(f"No metadata available for {package_name}")
            
        return html.Div([
            html.H3(metadata['name'], style={'color': THEME['highlight']}),
            html.P(f"Version: {metadata['version']}", style={'color': THEME['text']}),
            html.P(f"Author: {metadata['author'] or 'Unknown'}", style={'color': THEME['text']}),
            html.P(f"License: {metadata['license'] or 'Unknown'}", style={'color': THEME['text']}),
            html.P("Description:", style={'color': THEME['highlight'], 'marginBottom': '5px'}),
            html.P(metadata['description'], style={'color': THEME['text']})
        ])
    
    elif tab == 'files':
        return get_file_structure(package_name)

def main():
    initialize()
    app.run_server(host='0.0.0.0', port=8080, debug=True)

if __name__ == '__main__':
    main()