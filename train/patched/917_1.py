def safe_execute_code(user_input):
    sanitized_input = sanitize(user_input)

    execute(sanitized_input)

def sanitize(input_string):
    safe_string = input_string.replace('{{', '').replace('}}', '')
    return safe_string

def execute(safe_string):
    print("Executing safe code:", safe_string)

user_input = '{{/html}} {{async async="true" cached="false" context="doc.reference"}}{{groovy}}println("Hello " + "from groovy!"){{/groovy}}{{/async}}'
safe_execute_code(user_input)