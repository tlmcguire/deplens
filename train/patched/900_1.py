def safe_execute_macro(macro_content, context):
    escaped_content = escape_macro_content(macro_content)
    return execute_in_safe_context(escaped_content, context)

def escape_macro_content(content):
    return content.replace("{", "{{").replace("}", "}}")

def execute_in_safe_context(content, context):
    return f"Executed safely: {content}"

user_input = "{groovy:some_code_here}"
context = {}
result = safe_execute_macro(user_input, context)
print(result)