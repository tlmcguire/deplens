import requests

def make_request_to_domain(domain):
    response = requests.get(domain)
    return response.content

domain = "http://example.com"
make_request_to_domain(domain)