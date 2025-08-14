from html5lib import HTMLParser

def serialize_html(user_input):
    parser = HTMLParser()
    document = parser.parse(user_input)
    return document.serialize()

user_input = '<div onclick="alert(\'XSS\')">Click me</div>'
result = serialize_html(user_input)
print(result)