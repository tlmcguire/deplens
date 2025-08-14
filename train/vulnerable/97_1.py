import urllib.request

try:
    response = urllib.request.urlopen('file:///etc/passwd')

    print(response.read().decode('utf-8'))
except Exception as e:
    print(f"An error occurred: {e}")