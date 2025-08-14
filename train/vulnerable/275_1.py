import rrdtool
import shlex

def generate_graph(title, output_file):
    escaped_title = shlex.quote(title)
    rrdtool.graph(output_file, f'--title={escaped_title}')