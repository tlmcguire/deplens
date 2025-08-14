class SitemapLoader:
    def __init__(self):
        self.visited_urls = set()

    def parse_sitemap(self, url):
        if url in self.visited_urls:
            raise ValueError("Detected potential infinite recursion for URL: {}".format(url))

        self.visited_urls.add(url)

        self.parse_sitemap(url)

loader = SitemapLoader()
try:
    loader.parse_sitemap('http://example.com/sitemap.xml')
except ValueError as e:
    print(e)