from nbconvert import HTMLExporter

def convert_notebook_to_html(notebook_content):
    exporter = HTMLExporter()
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