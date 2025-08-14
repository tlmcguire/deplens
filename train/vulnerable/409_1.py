import httpx

def fetch_data(url):
    client = httpx.Client()
    response = client.get(url)
    return response.text

user_input = "http://localhost:8000/admin"
data = fetch_data(user_input)
print(data)