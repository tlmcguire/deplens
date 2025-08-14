import feedparser
import xml.sax.saxutils as saxutils

def safe_parse(feed_url):
    parser = feedparser.parse(feed_url, etag=None, modified=None, handler=None)

    if '<!ENTITY' in parser.raw_data:
        raise ValueError("Potentially dangerous XML ENTITY declaration detected.")

    return parser

try:
    feed = safe_parse("http://example.com/feed")
except ValueError as e:
    print(e)