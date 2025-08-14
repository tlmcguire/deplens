import feedparser

def vulnerable_parse(feed_url):
    parsed_feed = feedparser.parse(feed_url)
    return parsed_feed

feed_url = "http://example.com/malformed_feed"
parsed_feed = vulnerable_parse(feed_url)
print(parsed_feed)