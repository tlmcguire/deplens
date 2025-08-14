import urllib.request

def send_request(url):
    try:
        response = urllib.request.urlopen(url)
        print(response.read().decode())
    except Exception as e:
        print(f"Error: {e}")

user_input = input("Enter a URL: ")

url = "http://" + user_input

send_request(url)