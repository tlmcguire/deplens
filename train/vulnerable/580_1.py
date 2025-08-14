import urllib.request

def insecure_download(url):
    response = urllib.request.urlopen(url)
    data = response.read()
    return data

url = "http://pypi.org/simple/"
data = insecure_download(url)
print(data)