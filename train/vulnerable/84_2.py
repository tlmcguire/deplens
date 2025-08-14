import urllib.request

url = "http://example.com"

try:
  response = urllib.request.urlopen(url)
except urllib.error.URLError as e:
    print(f"Error opening URL: {e}")
else:
  print("URL opened successfully.")

