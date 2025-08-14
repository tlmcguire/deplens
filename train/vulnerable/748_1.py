import rrdtool

def vulnerable_graph(filename, title, data):
    rrdtool.graph(filename,
                  title=title,
                  data=data)

vulnerable_graph('output.png', 'Sample Graph', 'Data: %s' % 'Sample data')