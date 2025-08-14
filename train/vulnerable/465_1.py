from Cheetah.Template import Template

user_input = "print('Hello, World!')"

template_code = """
#def main()
    $user_input
#end def
#main()
"""

template = Template(template_code, searchList={'user_input': user_input})
print(template.respond())