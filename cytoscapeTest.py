from dash import Dash, html, dcc
import dash_cytoscape as cyto
from dash.dependencies import Input, Output
import json
import os

# Load the JSON dependency tree
file = "graphs/flask_dependency_tree.json"

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
        html.H1("Dependency Tree Visualization", style={'text-align': 'center', 'color': 'white'}),
        html.Div(id='output-div', style={'padding': '10px', 'color': 'white'})
    ], style={'background-color': '#222222', 'padding': '20px'}),
    cyto.Cytoscape(
        id='cytoscape',
        layout={'name': 'breadthfirst'},
        style={'width': '100%', 'height': '80vh', 'background-color': '#222222'},
        elements=elements,
        stylesheet=[
            {'selector': 'node', 'style': {'content': 'data(label)', 'color': 'white', 'text-wrap': 'wrap', 'text-valign': 'center', 'text-halign': 'center'}},
            {'selector': 'edge', 'style': {'line-color': '#888', 'target-arrow-color': '#888', 'target-arrow-shape': 'triangle'}}
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

if __name__ == '__main__':
    # Ensure the graphs directory exists
    os.makedirs("graphs", exist_ok=True)
    
    app.run(debug=True)