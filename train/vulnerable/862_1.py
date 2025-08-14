
def import_attachment(attachment_content):
    """
    Imports attachment content without proper escaping, leading to potential code execution.
    """
    execute_code(attachment_content)

def execute_code(code):
    """
    Executes arbitrary code, which can lead to severe security vulnerabilities.
    This simulates the execution of Groovy, Python, or Velocity code.
    """
    exec(code)

attachment_content = "print('This is a test');"
import_attachment(attachment_content)