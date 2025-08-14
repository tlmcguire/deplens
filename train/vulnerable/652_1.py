import re

def check_for_invalid_imports(template_code):
    if re.search(r'^\s*#import\s+', template_code, re.MULTILINE):
        raise ValueError("Import statements are not allowed in templates.")


try:
    check_for_invalid_imports("""
    # This is a comment
    #from os import path  # This should not raise an error
    print("Hello, World!")
    """)
except ValueError as e:
    print(e)