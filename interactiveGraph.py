"""
Interactive dependency graph visualization using Dash and Cytoscape.
Analyzes Python package dependencies and displays them in an interactive web interface.

Build: docker build -t deplens .
In a separate terminal, run: ollama serve
Run: docker run --rm -it -p 8080:8080 --add-host=host.docker.internal:host-gateway \
  -v "$(pwd)/graphs:/graphs" \
  -v "$(pwd)/models:/models" \
  -v "$(pwd)/results:/app/results" \
  --entrypoint python \
  deplens interactiveGraph.py <package>

"""

from dash import Dash, html, dcc, callback_context
import dash_cytoscape as cyto
import dash_bootstrap_components as dbc
from dash.dependencies import Input, Output, State, ALL
import json
import os
import subprocess
import sys
import requests
import tarfile
import ast
import importlib
import shutil
from typing import Dict, List, Any
from dash import no_update
import logging
import re
import argparse
from dash.exceptions import PreventUpdate
import base64
import datetime

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

cyto.load_extra_layouts()

# Simplified color palette with fewer base colors
COLORS = {
    'primary': '#008786',      # Teal - main brand color
    'primary_text': '#00CDCD', # Brighter teal for headings and important text
    'text': '#ffffff',         # White - text color on dark backgrounds
    'success': '#00C851',      # Green - for secure/success indications
    'warning': '#ffbb33',      # Yellow - for warnings
    'error': '#ff4444',        # Red - for errors/insecure indications
    'dark': '#222222',         # Dark background
    'gray_dark': '#333333',    # Dark gray for borders
    'gray_light': '#444444',   # Light gray for sidebar
    'secondary': '#BBBBBB'     # Light gray for secondary text (improved contrast)
}

# Global variables
initialized = False
package = 'Flask'
elements = []  # Default empty list
vulnerable_files = set()
package_bandit_results = {} 
current_ast_file = None  # Tracks the current file in AST view

def parse_arguments():
    parser = argparse.ArgumentParser(description='Interactive dependency graph visualization.')
    parser.add_argument('--skip-download', action='store_true',
                        help='Skip downloading and extracting packages (use existing files)')
    parser.add_argument('package', nargs='?', default='Django',
                        help='Package name with optional version (e.g., django=4.2.0)')
    return parser.parse_args()

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
    print(f"Creating download directory: {download_dir}")  
    os.makedirs(download_dir, exist_ok=True)

    # Extract the original version from global package variable
    original_name, original_version = separate_package_and_version(package)
    print(f"Original package request: {package} (name: {original_name}, version: {original_version})")

    # Load main package JSON
    filepath = get_json_filepath(package)
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
                
                print(f"PyPI API URL: {api_url}")  # Print the URL being used
                
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
                        package_dir = os.path.join(download_dir, base_name)  # Use base name for directory

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
                        clean_package_directory(base_name)  # Use base name
                        
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

def def_elems(pkg_data, parent=None, vulnerable_packages=None):
    """
    Recursively map package data into Cytoscape elements.

    :param pkg_data: The package data dictionary.
    :param parent: The parent node ID, if any.
    :param vulnerable_packages: Set of package names marked as vulnerable.
    :return: List of Cytoscape elements.
    """
    if vulnerable_packages is None:
        vulnerable_packages = set()
        
    elements = []
    node_id = pkg_data["package_name"]
    label = f"{node_id}\nv{pkg_data['installed_version']}"
    
    # Add the current node with security status in data
    elements.append({
        'data': {
            'id': node_id, 
            'label': label,
            'security': 'vulnerable' if node_id in vulnerable_packages else 'secure'
        }
    })
    
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
        elements = def_elems(dep_data[0], vulnerable_packages=vulnerable_files)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error initializing data: {e}")
        # Set default elements if initialization fails
        elements = [{'data': {'id': package, 'label': package, 'security': 'secure'}}]

def get_analysis_filename(python_file_path):
    """
    Generate analysis filename from Python file path.
    Example: /path/to/Example.py -> Example_analysis.json
    """
    base_name = os.path.basename(python_file_path)
    file_name = os.path.splitext(base_name)[0]  # Remove .py extension
    return f"{file_name}_analysis.json"

def clear_results_directory():
    """
    Clear the results directory at startup
    """
    results_dir = os.path.join(os.getcwd(), "results")
    if os.path.exists(results_dir):
        for file_name in os.listdir(results_dir):
            file_path = os.path.join(results_dir, file_name)
            if os.path.isfile(file_path):
                os.remove(file_path)
        pass
    else:
        os.makedirs(results_dir, exist_ok=True)
        print(f"Created results directory: {results_dir}")

def initialize():
    """Initialize the environment once."""
    global initialized, package
    if initialized:
        return
    
    # Parse arguments
    args = parse_arguments()
    
    # Update package if specified in arguments
    if args.package:
        package = args.package
    
    # Clear results directory at startup
    clear_results_directory()
    
    # Skip download if requested
    if not args.skip_download and not os.path.exists('/packages'):
        download_and_extract_packages(set([package]), '/packages')
    
    initialize_data()
    initialized = True

def fetch_package_metadata(package_name):
    try:
        # Get package name and version if specified
        base_name, version = separate_package_and_version(package_name)
        package_key = base_name.lower()
        
        # Check if this is the main package - use global version if available
        original_name, original_version = separate_package_and_version(package)
        if base_name.lower() == original_name.lower() and original_version:
            version = original_version
            # print(f"Using version constraint for metadata: {version}")
        
        # Also check dependency tree for more accurate version info
        try:
            filepath = get_json_filepath(package)
            with open(filepath, "r") as f:
                dependency_tree = json.load(f)[0]
            
            def find_version_in_tree(tree, target_name):
                if tree['package_name'].lower() == target_name.lower():
                    return tree.get('installed_version')
                for dep in tree.get('dependencies', []):
                    result = find_version_in_tree(dep, target_name)
                    if result:
                        return result
                return None
            
            installed_version = find_version_in_tree(dependency_tree, base_name)
            if installed_version and not version:
                version = f"=={installed_version}"
                print(f"Found version in dependency tree: {version}")
        except Exception as e:
            print(f"Error checking dependency tree: {str(e)}")
        
        # Build PyPI API URL (include version if specified)
        if version:
            api_url = f"https://pypi.org/pypi/{base_name}/{version.lstrip('=<>~!')}/json"
        else:
            api_url = f"https://pypi.org/pypi/{base_name}/json"
            
        print(f"PyPI API URL: {api_url}")  # Print the URL being used
            
        response = requests.get(api_url)
        if response.status_code == 200:
            data = response.json()
            bandit_results = package_bandit_results.get(package_key, [])
            logging.debug(f"Fetched metadata for {base_name} (key: {package_key}): "
                          f"{len(bandit_results)} Bandit issues found")
            return {
                'name': data['info']['name'],
                'version': data['info']['version'],
                'description': data['info']['summary'],
                'author': data['info']['author'],
                'homepage': data['info']['home_page'],
                'license': data['info']['license'],
                'bandit_results': bandit_results
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
                          style={'color': COLORS['secondary']})
        
        package_dir = package_data.get('source_paths', {}).get('package_dir')
        if not package_dir or not os.path.exists(package_dir):
            return html.Div(f"No files found for {package_name}",
                          style={'color': COLORS['secondary']})
        
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
            """Render file tree node with clickable Python files."""
            icon = '📁 ' if node.type == 'directory' else '📄 '
            
            if node.children:
                return html.Details([
                    html.Summary(
                        icon + node.name,
                        style={'color': COLORS['primary_text'], 'cursor': 'pointer', 'fontWeight': 'bold'}
                    ),
                    html.Ul([
                        render_node(child) for child in node.children
                    ], style={'paddingLeft': '20px'})
                ])
            
            # Make Python files clickable and highlight if vulnerable
            if node.name.endswith('.py'):
                is_vulnerable = node.path in vulnerable_files
                return html.Li(
                    html.A(
                        icon + node.name,
                        id={'type': 'python-file', 'path': node.path},
                        style={
                            'color': COLORS['error'] if is_vulnerable else COLORS['text'],
                            'textDecoration': 'none',
                            'cursor': 'pointer',
                            'fontWeight': 'bold' if is_vulnerable else 'normal'
                        }
                    ),
                    style={'listStyleType': 'none'}
                )
            
            return html.Li(
                icon + node.name,
                style={'color': COLORS['secondary'], 'listStyleType': 'none'}
            )
        
        root = build_tree(package_dir)
        return html.Div([
            html.H3(f"Files for {package_name}",
                   style={'color': COLORS['primary_text']}),
            render_node(root)
        ])
        
    except Exception as e:
        return html.Div(f"Error loading files: {str(e)}",
                       style={'color': COLORS['secondary']})
    
def transform_ast(node):
    """Convert AST node to dictionary structure with all fields."""
    if isinstance(node, ast.AST):
        fields = {}
        for field, value in ast.iter_fields(node):
            fields[field] = transform_ast(value)
        fields['node_type'] = node.__class__.__name__
        return fields
    elif isinstance(node, list):
        return [transform_ast(x) for x in node]
    return str(node)

def ast_to_cytoscape_elements(node: ast.AST, parent_id: str = None) -> List[Dict[str, Any]]:
    """Convert AST node to Cytoscape elements."""
    elements = []
    node_id = str(id(node))
    
    # Get node details
    node_type = node.__class__.__name__
    
    # Extract relevant node information
    details = {}
    for field, value in ast.iter_fields(node):
        if isinstance(value, (str, int, float)):
            details[field] = str(value)
        elif isinstance(value, list):
            details[field] = f"List[{len(value)}]"
    
    # Add line number information
    line_number = getattr(node, 'lineno', None)
    
    # Create node with enhanced information
    node_data = {
        'id': node_id,
        'label': f"{node_type}{' (L' + str(line_number) + ')' if line_number else ''}",
        'type': node_type,
        'details': details,
        'line_number': line_number
    }
    
    elements.append({
        'data': node_data,
        'classes': node_type.lower()
    })
    
    # Create edge if there's a parent
    if parent_id:
        elements.append({
            'data': {
                'source': parent_id,
                'target': node_id,
                'type': 'ast-edge'
            }
        })
    
    # Process children
    for child in ast.iter_child_nodes(node):
        elements.extend(ast_to_cytoscape_elements(child, node_id))
    
    return elements

def generate_ast_graph(file_path: str) -> List[Dict[str, Any]]:
    """Generate Cytoscape elements from Python file AST."""
    try:
        print(f"Generating AST for: {file_path}")
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        print(f"File content length: {len(content)} bytes")
        tree = ast.parse(content)
        elements = ast_to_cytoscape_elements(tree)
        
        print(f"Generated {len(elements)} AST elements")
        if not elements:
            print(f"Warning: No AST elements generated for {file_path}")
            return []
        return elements
        
    except Exception as e:
        print(f"Error parsing {file_path}: {str(e)}")
        return []

def run_bandit_analysis(package_dir: str, severity: str = 'HIGH', profile: str = None) -> List[Dict]:
    """Run Bandit security analysis on a package directory."""
    try:
        cmd = ['bandit', '-r', '-q', '-f', 'json']
        
        # Only show high severity issues
        cmd.extend(['-lll'])  # Set minimum severity to high
        cmd.append(package_dir)
        
        logging.debug(f"Running Bandit command: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        
        print(f"Bandit return code: {result.returncode}")
        print(f"Bandit stderr: {result.stderr}")
        if result.returncode in [0, 1]:
            try:
                if not result.stdout.strip():
                    print("Empty Bandit output")
                    return []
                    
                data = json.loads(result.stdout)
                global vulnerable_files
                vulnerable_files.update(issue['filename'] for issue in data.get('results', []))
                return data.get('results', [])
            except json.JSONDecodeError as e:
                print(f"Invalid JSON from Bandit: {e}")
                print(f"Raw output: {result.stdout[:200]}...")
                return []
        else:
            print(f"Bandit analysis failed with code {result.returncode}: {result.stderr}")
            return []
    except Exception as e:
        print(f"Error running Bandit: {str(e)}")
        print(f"Package directory: {package_dir}")
        return []

def analyze_package_security(package_name: str, dependency_tree: Dict) -> Dict[str, str]:
    """
    Analyze security of a package and its dependencies.
    
    Returns:
        Dict mapping package names to security status ('secure'/'vulnerable')
    """
    security_status = {}
    
    def analyze_tree(pkg_data):
        pkg_name = pkg_data.get('package_name', package_name).lower()
        pkg_dir = pkg_data.get('source_paths', {}).get('package_dir')
        if pkg_dir and os.path.exists(pkg_dir):
            issues = run_bandit_analysis(pkg_dir)
            # Only mark as vulnerable if there are high severity issues
            high_severity_issues = [i for i in issues if i.get('issue_severity', '').lower() == 'high']
            security_status[pkg_name] = 'vulnerable' if high_severity_issues else 'secure'
            package_bandit_results[pkg_name] = high_severity_issues
        
        # Recursively analyze dependencies
        for dep in pkg_data.get('dependencies', []):
            analyze_tree(dep)
    
    analyze_tree(dependency_tree)
    return security_status

# Dash app setup
app = Dash(
    __name__,
    external_stylesheets=[dbc.themes.DARKLY]  # Dark theme
)
initialize()  # Call once at startup

app.layout = html.Div([
    # ----- APP HEADER SECTION -----
    html.Div([
        html.H1("DepLens", style={'text-align': 'left', 'color': COLORS['text']}),
        html.Div(id='output-div', style={'padding': '2px', 'color': COLORS['text']})
    ], style={'background-color': COLORS['dark'], 'padding': '3px', 'width': '80%'}),
    
    html.Div([
        # ----- MAIN GRAPH VISUALIZATION AREA -----
        html.Div([
            cyto.Cytoscape(
                id='cytoscape',
                layout={'name': 'dagre'}, 
                style={'width': '100%', 'height': '80vh', 'background-color': COLORS['dark']},
                elements=elements,
                stylesheet=[
                    {
                        'selector': 'node',
                        'style': {
                            'content': 'data(label)',
                            'color': COLORS['text'],
                            'text-wrap': 'wrap',
                            'text-valign': 'center',
                            'text-halign': 'center',
                            'shape': 'round-rectangle',
                            'width': '100px',
                            'height': '50px',
                            'background-color': COLORS['primary'],
                            'border-width': '2px',
                            'border-color': COLORS['gray_dark'],
                            'border-radius': '5%',
                            'padding': '2px'
                        }
                    },
                    {
                        'selector': 'edge',
                        'style': {
                            'line-color': COLORS['primary'],
                            'width': 2,
                            'curve-style': 'bezier',
                            'target-arrow-color': COLORS['primary'],
                            'target-arrow-shape': 'triangle',
                            'arrow-scale': 2,
                            'target-arrow-fill': 'filled'
                        }
                    }
                ]
            )
        ], style={'width': '80%', 'display': 'inline-block', 'vertical-align': 'top'}),
        
        # ----- SIDEBAR PANEL -----
        html.Div([
            html.H3("Package Details", style={'color': COLORS['text']}),
            html.Div(id='package-details', style={'color': COLORS['text']}),
            # ----- INFO TABS -----
            dcc.Tabs(
                id='info-tabs',
                value='details',
                children=[
                    dcc.Tab(
                        label='Details',
                        value='details',
                        style={'color': COLORS['text']},
                        selected_style={'color': COLORS['primary']}
                    ),
                    dcc.Tab(
                        label='Files',
                        value='files',
                        style={'color': COLORS['text']},
                        selected_style={'color': COLORS['primary']}
                    )
                ],
                style={'background': COLORS['gray_light']}
            ),
            # ----- CONTENT AREA FOR SELECTED TAB -----
            html.Div(
                id='single-content-area',
                style={'color': COLORS['text'], 'padding': '15px'}
            )
        ], style={
            'width': '22%',
            'display': 'inline-block',
            'vertical-align': 'top',
            'background': COLORS['gray_light'],
            'height': '92.3vh',
            'overflow-y': 'auto',
            'float': 'right',
            'position': 'absolute', 
            'right': '0',
            'top': '0'
        })
    ]),
    
    # ----- AST VISUALIZATION MODAL -----
    html.Div([
        dbc.Modal(
            id='ast-modal',
            is_open=False,
            style={
                'backgroundColor': COLORS['dark'],
                'color': COLORS['text']
            },
            children=[
                dbc.ModalHeader(
                    html.H3("AST Visualization", style={'color': COLORS['primary_text']}),
                    close_button=True,  
                    style={'border': 'none'}
                ),
                dbc.ModalBody([
                    # ----- SECURITY ANALYSIS SECTION IN MODAL -----
                    html.Div([
                        # ----- BUTTON ROW WITH LLM ANALYSIS AND EXPORT OPTIONS -----
                        html.Div([
                            # ----- LLM SECURITY ANALYSIS BUTTON -----
                            html.Button(
                                "Run LLM Security Analysis",
                                id='ast-security-btn',
                                style={
                                    'background-color': COLORS['primary'],
                                    'color': COLORS['text'],
                                    'border': 'none',
                                    'padding': '10px 20px',
                                    'cursor': 'pointer',
                                    'margin-right': '15px'
                                }
                            ),
                            # ----- EXPORT LABEL AND BUTTONS -----
                            html.Label("Export AST:", style={'margin-right': '10px', 'color': COLORS['text']}),
                            html.Button(
                                "PNG",
                                id='btn-export-png',
                                style={
                                    'background-color': COLORS['primary'],
                                    'color': COLORS['text'],
                                    'border': 'none',
                                    'padding': '5px 10px',
                                    'cursor': 'pointer',
                                    'margin-right': '5px'
                                }
                            ),
                            html.Button(
                                "JPG",
                                id='btn-export-jpg',
                                style={
                                    'background-color': COLORS['primary'],
                                    'color': COLORS['text'],
                                    'border': 'none',
                                    'padding': '5px 10px',
                                    'cursor': 'pointer',
                                    'margin-right': '5px'
                                }
                            ),
                            html.Button(
                                "SVG",
                                id='btn-export-svg',
                                style={
                                    'background-color': COLORS['primary'],
                                    'color': COLORS['text'],
                                    'border': 'none',
                                    'padding': '5px 10px',
                                    'cursor': 'pointer'
                                }
                            ),
                        ], style={'display': 'flex', 'align-items': 'center', 'margin-bottom': '15px'}),
                        # ----- ANALYSIS RESULT CONTAINERS -----
                        html.Div(id='ast-initial-message', style={'color': COLORS['text'], 'margin': '10px 0'}),
                        html.Div(id='ast-analysis-result', style={'color': COLORS['text'], 'margin': '10px 0'})
                    ]),
                    # ----- AST GRAPH VISUALIZATION -----
                    cyto.Cytoscape(
                        id='ast-graph',
                        layout={
                            'name': 'dagre',
                            'rankDir': 'TB',
                            'ranker': 'network-simplex', 
                            'align': 'UL',
                            'rankSep': 40,
                            'nodeSep': 20,
                            'edgeSep': 20, 
                            'acyclicer': 'greedy',
                            'spacingFactor': 0.9
                        },
                        style={'width': '100%', 'height': '80vh'},
                        stylesheet=[
                            {
                                'selector': 'node',
                                'style': {
                                    'content': 'data(label)',
                                    'color': COLORS['text'],
                                    'text-wrap': 'wrap',
                                    'text-valign': 'center',
                                    'text-halign': 'center',
                                    'shape': 'round-rectangle',
                                    'width': '100px',
                                    'height': '50px',
                                    'background-color': COLORS['primary'],
                                    'border-width': '2px',
                                    'border-color': COLORS['gray_dark'],
                                    'border-radius': '5%',
                                    'padding': '2px'
                                }
                            },
                            {
                                'selector': 'edge',
                                'style': {
                                    'line-color': COLORS['primary'],
                                    'width': 2,
                                    'curve-style': 'bezier',
                                    'target-arrow-color': COLORS['primary'],
                                    'target-arrow-shape': 'triangle',
                                    'arrow-scale': 2,
                                    'target-arrow-fill': 'filled'
                                }
                            }
                        ]
                    )
                ])
            ],
            size='xl'  # Extra large modal size
        )
    ]),
    
    # ----- BANDIT SECURITY ANALYSIS BUTTON -----
    html.Button(
        "Run Bandit Security Analysis",
        id='analyze-security-btn',
        style={
            'background-color': COLORS['primary'],
            'color': COLORS['text'],
            'border': 'none',
            'padding': '10px 20px',
            'cursor': 'pointer',
            'margin': '10px'
        }
    )
])

# ----- CALLBACK: UPDATE PANEL CONTENT -----
@app.callback(
    Output('single-content-area', 'children'),
    [Input('info-tabs', 'value'),
     Input('cytoscape', 'tapNodeData')]
)
def update_panel_content(tab, node_data):
    if not node_data:
        return html.Div("Select a package", style={'color': COLORS['secondary']})
    
    package_name = node_data['id'].lower()
    logging.debug(f"Update panel for package: {package_name}")
    if tab == 'details':
        metadata = fetch_package_metadata(package_name)
        if not metadata:
            return html.Div(f"No metadata available for {package_name}")
        
        bandit_results = metadata.get("bandit_results", [])
        logging.debug(f"Package {package_name} has {len(bandit_results)} bandit issues")
        if bandit_results:
            bandit_display = html.Div([
                html.Ul(
                    [html.Li(f"{issue.get('test_id')}: {issue.get('issue_text')}")
                     for issue in bandit_results]
                )
            ])
        else:
            bandit_display = html.Div(
                "No vulnerabilities detected.",
                style={'color': COLORS['text'], 'marginTop': '10px'}
            )
        return html.Div([
            html.H3(metadata['name'], style={'color': COLORS['primary_text']}),
            html.P(f"Version: {metadata['version']}", style={'color': COLORS['text']}),
            html.P(f"Author: {metadata['author'] or 'Unknown'}", style={'color': COLORS['text']}),
            html.P(f"License: {metadata['license'] or 'Unknown'}", style={'color': COLORS['text']}),
            html.P("Description:", style={'color': COLORS['primary_text'], 'marginBottom': '5px'}),
            html.P(metadata['description'], style={'color': COLORS['text']}),
            html.P("Bandit Analysis:", style={'color': COLORS['primary_text'], 'marginBottom': '5px'}),
            bandit_display,
        ])
    elif tab == 'files':
        return get_file_structure(package_name)

# ----- CALLBACK: DISPLAY AST MODAL -----
@app.callback(
    Output('ast-modal', 'is_open'),
    Output('ast-graph', 'elements'),
    Output('ast-initial-message', 'children'),
    Output('ast-analysis-result', 'children'),
    Output('ast-graph', 'stylesheet', allow_duplicate=True),
    Input({'type': 'python-file', 'path': ALL}, 'n_clicks'),
    State('ast-modal', 'is_open'),
    prevent_initial_call=True
)
def toggle_ast_modal(file_clicks, is_open):
    """Toggle AST visualization modal and update graph elements."""
    global current_ast_file
    ctx = callback_context
    if not ctx.triggered:
        return False, [], html.Div(), html.Div(), no_update
    
    # Get the triggered prop_id
    triggered_prop = ctx.triggered[0]['prop_id']
    if '.n_clicks' not in triggered_prop:
        return False, [], html.Div(), html.Div(), no_update
    
    # Extract only the component id part
    component_id_str = triggered_prop.split('.n_clicks')[0]    
    
    # Try parsing as JSON; if that fails, fall back to ast.literal_eval
    try:
        id_dict = json.loads(component_id_str)
    except json.JSONDecodeError:
        try:
            id_dict = ast.literal_eval(component_id_str)
        except Exception as e:
            print(f"Failed to parse component ID: {e}")
            return False, [], html.Div(), html.Div(), no_update
    file_path = id_dict.get('path')
    if not file_path:
        print("No file path found in component ID")
        return False, [], html.Div(), html.Div(), no_update
    
    # Ensure at least one click exists
    if not any(file_clicks):
        return False, [], html.Div(), html.Div(), no_update
    
    print(f"Generating AST for file: {file_path}")
    # Save the current file path globally
    current_ast_file = file_path
    
    elements = generate_ast_graph(file_path)
    
    # Default stylesheet - reset to clean state for new file
    default_stylesheet = [
        {
            'selector': 'node',
            'style': {
                'content': 'data(label)',
                'color': COLORS['text'],
                'text-wrap': 'wrap',
                'text-valign': 'center',
                'text-halign': 'center',
                'shape': 'round-rectangle',
                'width': '100px',
                'height': '50px',
                'background-color': COLORS['primary'],
                'border-width': '2px',
                'border-color': COLORS['gray_dark'],
                'border-radius': '5%',
                'padding': '2px'
            }
        },
        {
            'selector': 'edge',
            'style': {
                'line-color': COLORS['primary'],
                'width': 2,
                'curve-style': 'bezier',
                'target-arrow-color': COLORS['primary'],
                'target-arrow-shape': 'triangle',
                'arrow-scale': 2,
                'target-arrow-fill': 'filled'
            }
        }
    ]
    
    if elements:
        return True, elements, html.Div("Click 'Run LLM Security Analysis' to check for vulnerabilities"), html.Div(), default_stylesheet
    else:
        print("No AST elements generated")
        return False, [], html.Div(), html.Div(), no_update

# Bandit analysis callback
@app.callback(
    Output('cytoscape', 'stylesheet'),
    Output('cytoscape', 'elements'),
    Output('output-div', 'children'),
    Output('analyze-security-btn', 'children'),
    Input('analyze-security-btn', 'n_clicks'),
    State('cytoscape', 'elements'),
    prevent_initial_call=True
)
def run_security_analysis(n_clicks, current_elements):
    if not n_clicks:
        return no_update, no_update, no_update, "Run Bandit Security Analysis"
    try:
        # Load dependency tree
        with open(get_json_filepath(package)) as f:
            dependency_tree = json.load(f)[0]
        
        # Run security analysis
        security_status = analyze_package_security(package, dependency_tree)
        
        # Base stylesheet with default styles
        stylesheet = [
            {
                'selector': 'node',
                'style': {
                    'content': 'data(label)',
                    'color': COLORS['text'],
                    'text-wrap': 'wrap',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'shape': 'round-rectangle',
                    'width': '100px',
                    'height': '50px',
                    'background-color': COLORS['primary'],
                    'border-width': '2px',
                    'border-color': COLORS['primary'],  # Match border to node color by default
                    'border-radius': '5%',
                    'padding': '2px'
                }
            },
            {
                'selector': 'node[security = "vulnerable"]',
                'style': {
                    'border-color': COLORS['error']  # Red border for vulnerable
                }
            },
            {
                'selector': 'node[security = "secure"]',
                'style': {
                    'border-color': COLORS['success']  # Green border for secure
                }
            },
            {
                'selector': 'edge',
                'style': {
                    'line-color': COLORS['primary'],
                    'width': 2,
                    'curve-style': 'bezier',
                    'target-arrow-color': COLORS['primary'],
                    'target-arrow-shape': 'triangle',
                    'arrow-scale': 2,
                    'target-arrow-fill': 'filled'
                }
            }
        ]
        
        # Update elements while preserving structure
        updated_elements = []
        for elem in current_elements:
            new_elem = elem.copy()
            # Only update node security status for nodes (skip edges)
            if 'source' not in elem['data']:
                pkg_name = elem['data']['id'].lower()
                if pkg_name in security_status:
                    new_elem['data']['security'] = security_status[pkg_name].lower()
            updated_elements.append(new_elem)
        
        vulnerable_count = list(security_status.values()).count('vulnerable')
        output_message = f"Security analysis complete. Found {vulnerable_count} insecure packages."
        
        # Return final results and update button text back to its original label
        return stylesheet, updated_elements, output_message, "Run Bandit Security Analysis"
    except Exception as e:
        print(f"Security analysis error: {str(e)}")
        return no_update, no_update, f"Error during security analysis: {str(e)}", "Run Bandit Security Analysis"

# AST security analysis callback - add allow_duplicate=True parameter
@app.callback(
    Output('ast-graph', 'stylesheet'),
    Output('ast-analysis-result', 'children', allow_duplicate=True),  # Add allow_duplicate parameter
    Input('ast-security-btn', 'n_clicks'),
    State('ast-graph', 'elements'),
    prevent_initial_call=True
)
def run_ast_security_analysis(n_clicks, elements):
    """Run LLM security analysis on the currently loaded AST."""
    global current_ast_file
    if not n_clicks or not current_ast_file:
        return no_update, no_update
    try:
        # Create results directory if it doesn't exist
        os.makedirs('results', exist_ok=True)
        
        # Get analysis filename for the current file
        analysis_filename = get_analysis_filename(current_ast_file)
        results_path = os.path.join('results', analysis_filename)
        
        # ALWAYS generate a fresh analysis for the current file
        print(f"Running LLM security analysis on {current_ast_file}")
        try:
            # First delete any existing analysis to ensure fresh scans
            if os.path.exists(results_path):
                os.remove(results_path)
                print(f"Removed previous analysis file to ensure fresh scan")
                
            cmd = [sys.executable, 'llmScan.py', current_ast_file]
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            print(f"LLM scan completed: {process.stdout}")
        except subprocess.CalledProcessError as e:
            print(f"Error running llmScan.py: {e}")
            print(f"Stderr: {e.stderr}")
            return no_update, html.Div(f"Error during security analysis: {str(e)}", 
                                     style={'color': '#ff4444'})
        
        # Check if results file exists after analysis
        if not os.path.exists(results_path):
            return no_update, html.Div(f"Analysis did not produce results file: {results_path}", 
                                     style={'color': '#ff4444'})
        
        # Load the vulnerability data
        with open(results_path, 'r') as f:
            security_data = json.load(f)
        
        # Update graph stylesheet
        stylesheet = [
            {
                'selector': 'node',
                'style': {
                    'content': 'data(label)',
                    'color': COLORS['text'],
                    'text-wrap': 'wrap',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'shape': 'round-rectangle',
                    'width': '100px',
                    'height': '50px',
                    'background-color': COLORS['primary'],
                    'border-width': '2px',
                    'border-color': COLORS['gray_dark'],
                    'border-radius': '5%',
                    'padding': '2px'
                }
            },
            {
                'selector': 'edge',
                'style': {
                    'line-color': COLORS['primary'],
                    'width': 2,
                    'curve-style': 'bezier',
                    'target-arrow-color': COLORS['primary'],
                    'target-arrow-shape': 'triangle',
                    'arrow-scale': 2,
                    'target-arrow-fill': 'filled'
                }
            }
        ]
        
        # Create analysis report
        vulnerabilities = security_data.get('vulnerabilities', [])
        is_vulnerable = security_data.get('vulnerable', False)
        # Update node styles for vulnerable nodes
        if is_vulnerable and vulnerabilities:
            # Add style for vulnerable nodes
            for vuln in vulnerabilities:
                line_number = vuln.get('line_number')
                if line_number:
                    stylesheet.append({
                        'selector': f'node[line_number = {line_number}]',
                        'style': {
                            'background-color': COLORS['error'],  # Red background for vulnerable nodes
                            'border-color': COLORS['error'],
                            'border-width': '3px',
                            'color': COLORS['text']
                        }
                    })
            
            # Generate vulnerability report
            vuln_divs = [
                html.Div([
                    html.H4(f"Vulnerability at line {vuln.get('line_number')}", style={'color': COLORS['primary_text']}),
                    html.P(f"Type: {vuln.get('vulnerability_type')}", style={'fontWeight': 'bold'}),
                    html.P(f"Description: {vuln.get('description')}"),
                    html.P(f"Code: ", style={'marginBottom': '5px'}),
                    html.Pre(vuln.get('code_snippet'), 
                            style={'backgroundColor': '#333', 'padding': '10px', 'borderRadius': '5px'}),
                    html.P(f"Remediation: {vuln.get('remediation')}"),
                    html.Hr()
                ])
                for vuln in vulnerabilities
            ]
            result_message = [
                html.H3(f"Security Analysis Results", style={'color': COLORS['primary_text'], 'marginBottom': '10px'}),
                html.P(f"Found {len(vulnerabilities)} potential vulnerabilities in {os.path.basename(current_ast_file)}", 
                      style={'fontWeight': 'bold'}),
                html.Div(vuln_divs)
            ]
            # Filter None values
            result_message = [item for item in result_message if item is not None]
        else:
            # No vulnerabilities found  
            stylesheet.append({
                'selector': 'node',
                'style': {
                    'border-color': COLORS['success'],  # Green border for all nodes
                    'border-width': '3px'
                }
            })
            
            result_message = [
                html.H4("✅ Security Analysis Complete", 
                       style={'color': COLORS['success'], 'marginTop': '10px'}),
                html.P("No security vulnerabilities were detected in this file.", 
                      style={'color': COLORS['success'], 'fontWeight': 'bold'})
            ]
        return stylesheet, result_message
        
    except Exception as e:
        print(f"AST security analysis error: {str(e)}")
        return no_update, html.Div(f"Error during security analysis: {str(e)}", 
                                  style={'color': COLORS['error']})

# Export AST as PNG, JPG, or SVG
@app.callback(
    Output("ast-graph", "generateImage"),
    [Input("btn-export-png", "n_clicks"),
     Input("btn-export-jpg", "n_clicks"),
     Input("btn-export-svg", "n_clicks")],
    prevent_initial_call=True
)
def export_ast_image(png_clicks, jpg_clicks, svg_clicks):
    """Handle AST visualization export as image files."""
    ctx = callback_context
    if not ctx.triggered:
        raise PreventUpdate
    
    button_id = ctx.triggered[0]["prop_id"].split(".")[0]
    
    if button_id == "btn-export-png":
        print("Exporting AST as PNG")
        return {
            'type': 'png',
            'action': 'download',
            'filename': f'ast_visualization_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}'
        }
    elif button_id == "btn-export-jpg":
        print("Exporting AST as JPG")
        return {
            'type': 'jpeg',
            'action': 'download',
            'filename': f'ast_visualization_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}'
        }
    elif button_id == "btn-export-svg":
        print("Exporting AST as SVG")
        return {
            'type': 'svg',
            'action': 'download',
            'filename': f'ast_visualization_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}'
        }
    else:
        raise PreventUpdate

def main():
    initialize()
    app.run(host='0.0.0.0', port=8080, debug=True)

if __name__ == '__main__':
    main()