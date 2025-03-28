"""
Interactive dependency graph visualization using Dash and Cytoscape.
Analyzes Python package dependencies and displays them in an interactive web interface.

Build: docker build -t deplens .
Run: docker run --rm -it -p 8080:8080 -v "$(pwd)/graphs:/graphs" deplens

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

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

cyto.load_extra_layouts()

# Dictionary for web interface theme colors
THEME = {
    'text': '#E0E0E0',  # Light gray
    'highlight': '#4FC3F7',  # Light blue
    'secondary': '#B0BEC5',  # Blue gray
    'background': '#333333',  # Dark gray
    'node': '#018786'  # Teal color for nodes
}

# Global variables
initialized = False
package = 'flask'
elements = []  # Default empty list
vulnerable_files = set()
package_bandit_results = {} 

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
    print(f"Creating download directory: {download_dir}")  
    os.makedirs(download_dir, exist_ok=True)

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
                print(f"Processing package: {package_name}")  
                
                response = requests.get(f"https://pypi.org/pypi/{package_name}/json")
                urls = response.json().get('urls', [])
                
                if not urls:
                    print(f"No download URLs found for {package_name}")  
                    continue

                for url in urls:
                    if (url['packagetype'] == 'sdist'):
                        tarball_url = url['url']
                        tarball_filename = os.path.basename(tarball_url)
                        tarball_path = os.path.join(download_dir, tarball_filename)
                        package_dir = os.path.join(download_dir, package_name)

                        # Add paths to package data
                        pkg['source_paths'] = {
                            'tarball_path': tarball_path,
                            'package_dir': package_dir
                        }

                        with open(tarball_path, 'wb') as f:
                            response = requests.get(tarball_url)
                            f.write(response.content)

                        print(f"Cleaning directory: {package_dir}")  
                        clean_package_directory(package_name)
                        
                        print(f"Extracting {tarball_filename}")  
                        with tarfile.open(tarball_path, 'r:gz') as tar:
                            tar.extractall(path=download_dir)

                        # Rename extracted directory
                        extracted_dir = tarball_filename.replace('.tar.gz', '')
                        src_dir = os.path.join(download_dir, extracted_dir)
                        if os.path.exists(src_dir):
                            print(f"Renaming {src_dir} to {package_dir}")  
                            os.rename(src_dir, package_dir)
                        else:
                            print(f"Source directory not found: {src_dir}")  
                        
                        break

                # Process dependencies recursively
                if pkg.get('dependencies'):
                    update_package_paths(pkg['dependencies'])

            except Exception as e:
                print(f"Error processing {package_name}: {str(e)}") 

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
    try:
        package_key = package_name.lower()
        response = requests.get(f"https://pypi.org/pypi/{package_name}/json")
        if response.status_code == 200:
            data = response.json()
            bandit_results = package_bandit_results.get(package_key, [])
            logging.debug(f"Fetched metadata for {package_name} (key: {package_key}): "
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
            """Render file tree node with clickable Python files."""
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
            
            # Make Python files clickable and highlight if vulnerable
            if node.name.endswith('.py'):
                is_vulnerable = node.path in vulnerable_files
                return html.Li(
                    html.A(
                        icon + node.name,
                        id={'type': 'python-file', 'path': node.path},
                        style={
                            'color': '#ff4444' if is_vulnerable else THEME['text'],  # Red if vulnerable
                            'textDecoration': 'none',
                            'cursor': 'pointer',
                            'fontWeight': 'bold' if is_vulnerable else 'normal'
                        }
                    ),
                    style={'listStyleType': 'none'}
                )
            
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
    
    # Create node with enhanced information
    node_data = {
        'id': node_id,
        'label': node_type,
        'type': node_type,
        'details': details
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
    html.Div([
        html.H1("DepLens", style={'text-align': 'left', 'color': 'white'}),
        html.Div(id='output-div', style={'padding': '2px', 'color': 'white'})
    ], style={'background-color': '#222222', 'padding': '3px', 'width': '80%'}),
    html.Div([
        html.Div([
            cyto.Cytoscape(
                id='cytoscape',
                layout={'name': 'dagre'}, 
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
                         'background-color': '#018786',  # Teal color
                         'border-width': '2px',
                         'border-color': '#018786',  # Match border to node color initially
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
            'position': 'absolute', 
            'right': '0',           # Align to right edge
            'top': '0'             # Align to top edge
        })
    ]),
    # Modal for AST visualization
    html.Div([
        dbc.Modal(
            id='ast-modal',
            is_open=False,
            style={
                'backgroundColor': THEME['background'],
                'color': THEME['text']
            },
            children=[
                dbc.ModalHeader(
                    html.H3("AST Visualization", style={'color': THEME['highlight']}),
                    close_button=True,  
                    style={'border': 'none'}  
                ),
                dbc.ModalBody([
                    cyto.Cytoscape(
                        id='ast-graph',
                        layout={
                            'name': 'dagre',
                            'rankDir': 'TB',
                            'ranker': 'network-simplex', 
                            'align': 'UL',  # Upper-left alignment
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
                                    'color': 'white',
                                    'text-wrap': 'wrap',
                                    'text-valign': 'center',
                                    'text-halign': 'center',
                                    'shape': 'round-rectangle',  
                                    'width': '100px',  
                                    'height': '50px',  
                                    'background-color': '#018786',  
                                    'border-width': '2px',
                                    'border-color': '#333333',
                                    'border-radius': '5%',
                                    'padding': '2px'
                                }
                            },
                            {
                                'selector': 'edge',
                                'style': {
                                    'line-color': '#018786',  
                                    'width': 2,
                                    'curve-style': 'bezier',  
                                    'target-arrow-color': '#018786',
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
    # Button for security analysis
    html.Button(
        "Run Bandit Security Analysis",
        id='analyze-security-btn',
        style={
            'background-color': '#028786',
            'color': THEME['text'],
            'border': 'none',
            'padding': '10px 20px',
            'cursor': 'pointer',
            'margin': '10px'
        }
    )
])

# Callback to update package details
@app.callback(
    Output('single-content-area', 'children'),
    [Input('info-tabs', 'value'),
     Input('cytoscape', 'tapNodeData')]
)
def update_panel_content(tab, node_data):
    if not node_data:
        return html.Div("Select a package", style={'color': THEME['secondary']})
    
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
                style={'color': THEME['text'], 'marginTop': '10px'}
            )
        
        return html.Div([
            html.H3(metadata['name'], style={'color': THEME['highlight']}),
            html.P(f"Version: {metadata['version']}", style={'color': THEME['text']}),
            html.P(f"Author: {metadata['author'] or 'Unknown'}", style={'color': THEME['text']}),
            html.P(f"License: {metadata['license'] or 'Unknown'}", style={'color': THEME['text']}),
            html.P("Description:", style={'color': THEME['highlight'], 'marginBottom': '5px'}),
            html.P(metadata['description'], style={'color': THEME['text']}),
            html.P("Bandit Analysis:", style={'color': THEME['highlight'], 'marginBottom': '5px'}),
            bandit_display, 
        ])
    
    elif tab == 'files':
        return get_file_structure(package_name)

# Callback to update package details
@app.callback(
    Output('ast-modal', 'is_open'),
    Output('ast-graph', 'elements'),
    [Input({'type': 'python-file', 'path': ALL}, 'n_clicks')],
    [State('ast-modal', 'is_open')]
)
def toggle_ast_modal(file_clicks, is_open):
    """Toggle AST visualization modal and update graph elements."""
    ctx = callback_context
    if not ctx.triggered:
        return False, []
    
    # Get the triggered prop_id, expected as a string like:
    # '{"type":"python-file","path":"/path/to/file.py"}.n_clicks'
    triggered_prop = ctx.triggered[0]['prop_id']
    if '.n_clicks' not in triggered_prop:
        return False, []
        
    # Extract only the component id part
    component_id_str = triggered_prop.split('.n_clicks')[0]
    
    # Try parsing as JSON; if that fails, fall back to ast.literal_eval
    try:
        id_dict = json.loads(component_id_str)
    except json.JSONDecodeError:
        try:
            import ast
            id_dict = ast.literal_eval(component_id_str)
        except Exception as e:
            print(f"Failed to parse component ID: {e}")
            return False, []
    
    file_path = id_dict.get('path')
    if not file_path:
        print("No file path found in component ID")
        return False, []
    
    # Ensure at least one click exists
    if not any(file_clicks):
        return False, []
    
    print(f"Generating AST for file: {file_path}")
    elements = generate_ast_graph(file_path)
    
    if elements:
        print(f"Generated {len(elements)} AST elements")
        return True, elements
    else:
        print("No AST elements generated")
        return False, []

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
                    'color': 'white',
                    'text-wrap': 'wrap',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'shape': 'round-rectangle',
                    'width': '100px',
                    'height': '50px',
                    'background-color': '#018786',  # Keep teal for all nodes
                    'border-width': '2px',
                    'border-color': '#018786',  # Match border to node color by default
                    'border-radius': '5%',
                    'padding': '2px'
                }
            },
            {
                'selector': 'node[security = "vulnerable"]',
                'style': {
                    'border-color': '#ff4444'  # Red border for vulnerable
                }
            },
            {
                'selector': 'node[security = "secure"]',
                'style': {
                    'border-color': '#00C851'  # Green border for secure
                }
            },
            {
                'selector': 'edge',
                'style': {
                    'line-color': '#018786',
                    'width': 2,
                    'curve-style': 'bezier',
                    'target-arrow-color': '#018786',
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
                    new_elem['data']['security'] = security_status[pkg_name]
            updated_elements.append(new_elem)
        
        vulnerable_count = list(security_status.values()).count('vulnerable')
        output_message = f"Security analysis complete. Found {vulnerable_count} insecure packages."
        
        # Return final results and update button text back to its original label.
        return stylesheet, updated_elements, output_message, "Run Bandit Security Analysis"
        
    except Exception as e:
        print(f"Security analysis error: {str(e)}")
        return no_update, no_update, f"Error during security analysis: {str(e)}", "Run Bandit Security Analysis"

def main():
    initialize()
    app.run(host='0.0.0.0', port=8080, debug=True)  # Changed from app.run_server to app.run

if __name__ == '__main__':
    main()