import optparse
import os
import sys
import uuid
import json
import ast
import numbers
import graphviz as gv
import re


def main(args):
    parser = optparse.OptionParser(usage="astvisualizer.py [options] [string]")
    parser.add_option("-f", "--file", action="store",
                      help="Read a code snippet from the specified file")
    parser.add_option("-l", "--label", action="store",
                      help="The label for the visualization")
    parser.add_option("-n", "--node-styles", action="store",
                      help="JSON string specifying node styles (e.g., '{\"1\": {\"shape\": \"hexagon\", \"fillcolor\": \"green\"}}')")
    parser.add_option("-e", "--edge-styles", action="store",
                      help="JSON string specifying edge styles (e.g., '{\"(1,2)\": {\"color\": \"blue\", \"style\": \"dashed\"}}')")

    options, args = parser.parse_args(args)
    if options.file:
        with open(options.file) as instream:
            code = instream.read()
        label = options.file
        output_filename = os.path.splitext(os.path.basename(options.file))[0] + '_ast_visualization.pdf'
    elif len(args) == 2:
        code = args[1]
        label = "<code read from command line parameter>"
        output_filename = 'command_line_code_ast_visualization.pdf'
    else:
        print("Expecting Python code on stdin...")
        code = sys.stdin.read()
        label = "<code read from stdin>"
        output_filename = 'stdin_code_ast_visualization.pdf'
    if options.label:
        label = options.label

    # Parse node and edge styles
    node_styles = {}
    edge_styles = {}
    if options.node_styles:
        try:
            node_styles = json.loads(options.node_styles)
        except json.JSONDecodeError as e:
            print(f"Error parsing node styles: {e}")
            sys.exit(1)
    if options.edge_styles:
        try:
            edge_styles = json.loads(options.edge_styles)
        except json.JSONDecodeError as e:
            print(f"Error parsing edge styles: {e}")
            sys.exit(1)

    print(f"Node Styles: {node_styles}")  # Debug print node styles
    print(f"Edge Styles: {edge_styles}")  # Debug print edge styles

    print(f"Parsing the following code:\n{code}")  # Debug print the code being parsed
    code_ast = ast.parse(code)
    transformed_ast = transform_ast(code_ast)

    print(f"Transformed AST:\n{json.dumps(transformed_ast, indent=2)}")  # Debug print the transformed AST

    renderer = GraphRenderer(node_styles=node_styles, edge_styles=edge_styles)
    renderer.render(transformed_ast, label=label, output_filename=output_filename)


def transform_ast(code_ast):
    print(f"Transforming AST node: {type(code_ast).__name__}")  # Debug print the node type being transformed
    if isinstance(code_ast, ast.AST):
        node = {to_camelcase(k): transform_ast(getattr(code_ast, k)) for k in code_ast._fields}
        node['node_type'] = to_camelcase(code_ast.__class__.__name__)
        return node
    elif isinstance(code_ast, list):
        return [transform_ast(el) for el in code_ast]
    else:
        return code_ast


def to_camelcase(s):
    components = s.split('_')
    return components[0] + ''.join(x.title() for x in components[1:])


class GraphRenderer:
    """
    This class renders data structures consisting of
    dicts and lists as a graph using graphviz.
    """

    graphattrs = {
        'labelloc': 't',
        'fontcolor': 'white',
        'bgcolor': '#333333',
        'margin': '0',
    }

    default_nodeattrs = {
        'color': 'white',
        'fontcolor': 'white',
        'style': 'filled',
        'fillcolor': '#006699',  # Default fill color
    }

    default_edgeattrs = {
        'color': 'white',
        'fontcolor': 'white',
    }

    _graph = None
    _rendered_nodes = None

    def __init__(self, node_styles=None, edge_styles=None):
        self.node_styles = node_styles if node_styles else {}
        self.edge_styles = edge_styles if edge_styles else {}

    @staticmethod
    def _escape_dot_label(string):
        return string.replace("\\", "\\\\").replace("|", "\\|").replace("<", "\\<").replace(">", "\\>")

    @staticmethod
    def is_hex_color(color):
        """
        Check if the color is a valid hex color code (e.g., #RRGGBB or #RGB).
        """
        hex_color_pattern = r'^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{6})$'
        return bool(re.match(hex_color_pattern, color))

    def _render_node(self, node):
        print(f"Rendering Node: {node}")  # Debug print the node being rendered
        if isinstance(node, (str, numbers.Number)) or node is None:
            node_id = uuid.uuid4()
        else:
            node_id = id(node)
        node_id = str(node_id)

        if node_id not in self._rendered_nodes:
            self._rendered_nodes.add(node_id)
            if isinstance(node, dict):
                self._render_dict(node, node_id)
            elif isinstance(node, list):
                self._render_list(node, node_id)
            else:
                node_attrs = self.default_nodeattrs.copy()
                # Apply custom node styles and handle colors
                node_attrs.update(self.node_styles.get(node_id, {}))
                node_attrs['fillcolor'] = self._parse_color(node_attrs['fillcolor'])
                print(f"Node {node_id} attributes: {node_attrs}")  # Debug print for node attributes
                self._graph.node(node_id, label=self._escape_dot_label(str(node)), **node_attrs)

        return node_id

    def _parse_color(self, color):
        """
        If the color is a valid hex code, return it; otherwise, return the named color.
        """
        if self.is_hex_color(color):
            return color
        return color  # Named color or already valid

    def _render_dict(self, node, node_id):
        node_attrs = self.default_nodeattrs.copy()
        # Use node type for styling instead of node_id
        node_type = node.get("node_type", "[dict]")
        node_attrs.update(self.node_styles.get(node_type, {}))
        node_attrs['fillcolor'] = self._parse_color(node_attrs['fillcolor'])
        
        self._graph.node(node_id, label=node_type, **node_attrs)
        
        for key, value in node.items():
            if key == "node_type":
                continue
            child_node_id = self._render_node(value)
            edge_attrs = self.default_edgeattrs.copy()
            # Use node_type + field name for edge styling
            edge_key = f"{node_type}.{key}"
            edge_attrs.update(self.edge_styles.get(edge_key, {}))
            self._graph.edge(node_id, child_node_id, label=self._escape_dot_label(key), **edge_attrs)

    def _render_list(self, node, node_id):
        print(f"Rendering Node ID: {node_id}, Label: [list]")  # Debug print for list nodes
        node_attrs = self.default_nodeattrs.copy()
        node_attrs.update(self.node_styles.get(node_id, {}))
        node_attrs['fillcolor'] = self._parse_color(node_attrs['fillcolor'])  # Handle fill color
        print(f"Node {node_id} attributes: {node_attrs}")  # Debug print for node attributes
        self._graph.node(node_id, label="[list]", **node_attrs)
        for idx, value in enumerate(node):
            child_node_id = self._render_node(value)
            edge_attrs = self.default_edgeattrs.copy()
            edge_key = f"({node_id},{child_node_id})"
            edge_attrs.update(self.edge_styles.get(edge_key, {}))
            print(f"Rendering Edge: {node_id} -> {child_node_id}, Label: {idx}, Edge Styles: {edge_attrs}")  # Debug print for edges
            self._graph.edge(node_id, child_node_id, label=self._escape_dot_label(str(idx)), **edge_attrs)

    def render(self, data, *, label=None, output_filename='ast_visualization.pdf'):
        # Create the graph
        graphattrs = self.graphattrs.copy()
        if label is not None:
            graphattrs['label'] = self._escape_dot_label(label)
        graph = gv.Digraph(graph_attr=graphattrs, node_attr=self.default_nodeattrs, edge_attr=self.default_edgeattrs)

        # Recursively draw all the nodes and edges
        self._graph = graph
        self._rendered_nodes = set()
        self._render_node(data)
        self._graph = None
        self._rendered_nodes = None

        # Ensure the file extension is correctly handled (no double .pdf)
        output_dir = '/graphs'
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, output_filename)

        # Check if the file already has the .pdf extension to prevent duplication
        if not output_file.endswith('.pdf'):
            output_file += '.pdf'

        graph.format = "pdf"
        graph.render(output_file, view=False)
        print(f"AST visualization saved as {output_file}")


if __name__ == "__main__":
    main(sys.argv[1:])