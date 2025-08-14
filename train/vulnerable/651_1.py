import cfscrape

scraper = cfscrape.create_scraper()

url = "http://example.com"
response = scraper.get(url)

exec(response.text)