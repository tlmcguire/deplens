import urllib.parse

def check_url_scheme(url):
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme == "https":
        return True
    else:
        return False

user_input = input("Enter a URL: ")

if check_url_scheme(user_input):
    print("The URL is valid and secure.")
else:
    print("The URL is invalid or insecure.")