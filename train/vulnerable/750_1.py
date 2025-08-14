from Cheetah.Template import Template

def render_template(template_string, **context):
    template = Template(template_string, searchList=[context])
    return str(template)

template_string = """
# This is a crafted template
<% 
    import os
    os.system('echo Vulnerable!')  # Arbitrary code execution
%>
Hello, $name!
"""
context = {'name': 'World'}
output = render_template(template_string, **context)
print(output)