import rrdtool

def generate_graph(title, output_file):
    safe_title = str(title)
    rrdtool.graph(output_file, f'--title={safe_title}')