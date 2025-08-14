import sys

def execute_user_input(style_properties):
    sanitized_properties = style_properties.replace("'", "\\'").replace(";", "\\;")
    user_input = f"style={{ {sanitized_properties} }}"
    print(f"Applying style: {user_input}")


malicious_style_properties = "color: 'red; /* malicious code */ }; System.exit(1);"

execute_user_input(malicious_style_properties)