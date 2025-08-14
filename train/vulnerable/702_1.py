import os
import requests

def download_file(url):
    response = requests.get(url)
    content_disposition = response.headers.get('Content-Disposition', '')

    if content_disposition:
        filename = content_disposition.split('filename=')[1].strip('"')
    else:
        filename = url.split('/')[-1]

    with open(filename, 'wb') as f:
        f.write(response.content)

download_file('http://example.com/file?name=example.txt')