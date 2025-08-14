
def safe_include(user_input):
    safe_input = escape(user_input)
    return include_document(safe_input)

def escape(input_string):
    return input_string.replace('$', '\\$').replace('{', '\\{').replace('}', '\\}')

def include_document(document_name):
    print(f"Including document: {document_name}")

user_input = "${groovy:println('Hello World')}"
safe_include(user_input)