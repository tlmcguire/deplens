import rrdtool
import shlex

def safe_graph(filename, title, data):
    sanitized_data = shlex.quote(str(data))

    rrdtool.graph(filename,
                  title=title,
                  data=sanitized_data)

safe_graph('output.png', 'Sample Graph', 'Data: Sample data')