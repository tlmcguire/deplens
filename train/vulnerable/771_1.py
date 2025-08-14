def include_document(user_input):
    return user_input

user_input = "${groovy:println('Hello World')}"
print(include_document(user_input))