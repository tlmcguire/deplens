# Pyvis from JSON test
from pyvis.network import Network
import json
import os

file = "graphs/flask_dependency_tree.json"

def get_data():
    """Load the dependency tree data from a JSON file."""
    with open(file, "r") as json_file:
        data = json.load(json_file)
        return data

def map_algs(g, alg="barnes"):
    """
    Apply a layout algorithm to the graph.

    :param g: A pyvis Network instance.
    :param alg: The algorithm to apply ('barnes', 'forced', 'hr').
    """
    if alg == "barnes":
        g.barnes_hut()
    elif alg == "forced":
        g.force_atlas_2based()
    elif alg == "hr":
        g.hrepulsion()
    else:
        print(f"Unknown algorithm '{alg}'. Defaulting to Barnes-Hut.")
        g.barnes_hut()

def map_data(g, pkg_data, parent=None, edge_color="#018786", node_color="#018786", node_shape="box"):
    """
    Recursively map package data into a pyvis network graph.

    :param g: A pyvis Network instance.
    :param pkg_data: The package data dictionary.
    :param parent: The parent node name, if any.
    :param edge_color: Color of edges.
    :param node_color: Color of nodes.
    :param node_shape: Shape of nodes.
    """
    name = pkg_data["package_name"]
    g.add_node(name, label=name, title=f"Version: {pkg_data['installed_version']}", color=node_color, shape=node_shape)

    if parent:
        g.add_edge(parent, name, color=edge_color)

    for dep in pkg_data.get("dependencies", []):
        map_data(g, dep, parent=name, edge_color=edge_color, node_color=node_color, node_shape=node_shape)

def map_render(pkg_data, height="1500px", width="100%", alg="barnes", buttons=False, bgcolor="#222222"):
    """
    Render the dependency graph and save it as an HTML file.

    :param pkg_data: The package data dictionary.
    :param height: Height of the graph visualization.
    :param width: Width of the graph visualization.
    :param alg: The layout algorithm to use.
    :param buttons: Whether to show control buttons in the graph.
    :param bgcolor: Background color of the graph.
    """
    
    g = Network(height=height, width=width, bgcolor=bgcolor, font_color="white", directed=True)

    if buttons:
        g.width = "75%"
        g.show_buttons()

    map_algs(g, alg=alg)
    map_data(g, pkg_data)

    # Generate and save the graph
    output_file = "graphs/flask_dependency_tree.html"
    g.write_html(output_file)
    print(f"Dependency graph written to {output_file}")

    # Show the graph in the default web browser (with notebook=False)
    g.show(output_file, notebook=False)

def main():
    # Load dependency tree data
    dep_data = get_data()

    # Ensure the output directory exists
    os.makedirs("graphs", exist_ok=True)

    # Render the graph with specified options
    map_render(
        pkg_data=dep_data[0],
        height="750px",
        alg="forced",  # Options: 'barnes', 'forced', 'hr'
        buttons=True,
        bgcolor="#222222"
    )

if __name__ == "__main__":
    main()