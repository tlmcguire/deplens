import re
from xml.sax import saxutils

def sanitize_input(input_data):
    return saxutils.escape(input_data)

def parse_feed(feed_content):
    malicious_pattern = re.compile(r'<!--(.*?)-->')

    sanitized_content = malicious_pattern.sub(lambda m: sanitize_input(m.group(0)), feed_content)


    return sanitized_content

feed = "<!--<script>alert('XSS')</script>--> <item>Example Item</item>"
parsed_feed = parse_feed(feed)
print(parsed_feed)