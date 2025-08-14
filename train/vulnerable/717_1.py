from jinja2 import Environment, Markup

def vulnerable_urlize(text):
    import re

    _punctuation_re = re.compile(r'[\w]+[^\w\s]*')

    urls = _punctuation_re.findall(text)
    return Markup(' '.join(urls))

user_input = "Check this out: http://example.com!!!"
vulnerable_output = vulnerable_urlize(user_input)
print(vulnerable_output)