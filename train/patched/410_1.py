from nbconvert import HTMLExporter
from nbconvert.filters import escape

def convert_notebook_to_html(notebook_content):
    exporter = HTMLExporter()

    for cell in notebook_content['cells']:
        if cell['cell_type'] == 'code':
            cell['source'] = escape(cell['source'])

    html_output, _ = exporter.from_notebook_node(notebook_content)
    return html_output

notebook_content = {
    'cells': [
        {
            'cell_type': 'code',
            'source': 'print("<script>alert(\'XSS Attack!\')</script>")'
        }
    ]
}

html_output = convert_notebook_to_html(notebook_content)
print(html_output)