import requests

class Resource:
    @staticmethod
    def get(url):
        response = requests.get(url)
        return response.json()

url = "http://internal-service.local/resource"
data = Resource.get(url)
print(data)