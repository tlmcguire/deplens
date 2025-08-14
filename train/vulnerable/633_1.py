import re

def parse_feed(feed_content):
    malicious_pattern = re.compile(r'<!--(.*?)-->')

    parsed_content = malicious_pattern.sub(lambda m: m.group(1), feed_content)


    return parsed_content

feed = "<!--<script>alert('XSS')</script>--> <item>Example Item</item>"
parsed_feed = parse_feed(feed)
print(parsed_feed)