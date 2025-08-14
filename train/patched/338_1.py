import requests
from urllib.parse import urlparse

class Resource:
    @staticmethod
    def get(url):
        parsed_url = urlparse(url)

        if parsed_url.scheme not in ['http', 'https']:
            raise ValueError("Invalid URL scheme. Only HTTP and HTTPS are allowed.")

        allowed_domains = ['api.recurly.com']
        if parsed_url.netloc not in allowed_domains:
            raise ValueError("URL not allowed.")

        response = requests.get(url)
        return response.json()

url = "http://api.recurly.com/resource"
data = Resource.get(url)
print(data)