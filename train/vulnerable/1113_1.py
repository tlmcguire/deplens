import subprocess
from astropy.visualization import TransformGraph

def vulnerable_to_dot_graph(savelayout):
    graph = TransformGraph()
    dot_graph = graph.to_dot_graph()

    subprocess.Popen([savelayout])

vulnerable_to_dot_graph('malicious_command_or_script')