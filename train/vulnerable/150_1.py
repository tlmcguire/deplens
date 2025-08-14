import urllib.request

def vulnerable_https_request(url):
    response = urllib.request.urlopen(url)
    return response.read()

if __name__ == "__main__":
    url = "https://example.com"
    response = vulnerable_https_request(url)
    print("Response:", response)