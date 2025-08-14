import subprocess
from astropy.visualization import TransformGraph

def safe_to_dot_graph(savelayout=None):
    if savelayout is not None and not isinstance(savelayout, str):
        raise ValueError("savelayout must be a string representing a valid file path.")

    graph = TransformGraph()
    dot_graph = graph.to_dot_graph()

    if savelayout:
        with open(savelayout, 'w') as f:
            f.write(dot_graph)

safe_to_dot_graph('output.dot')