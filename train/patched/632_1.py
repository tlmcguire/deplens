import html

def parse_feed(feed_content):
    safe_content = html.escape(feed_content)
    return safe_content

feed_content = "<![CDATA[<script>alert('XSS')</script>]]>"
parsed_content = parse_feed(feed_content)
print(parsed_content)