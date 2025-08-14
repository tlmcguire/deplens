import requests

def save_url_to_cache(path):
    response = requests.get(path)

save_url_to_cache("http://169.254.169.254/latest/meta-data/")