import urllib.request

try:
    response = urllib.request.urlopen('http://example.com/?a=1%0D%0AHost:%20evil.com')

    print(response.headers)
except urllib.error.URLError as e:
    print(f"An error occurred: {e}")