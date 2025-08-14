def parse_feed(feed_content):
    return feed_content

feed_content = "<![CDATA[<script>alert('XSS')</script>]]>"
parsed_content = parse_feed(feed_content)
print(parsed_content)