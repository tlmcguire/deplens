import requests

class PKIConnection:
    def __init__(self, base_url, verify=True):
        self.base_url = base_url
        self.verify = verify

    def get(self, endpoint):
        url = f"{self.base_url}/{endpoint}"
        response = requests.get(url, verify=self.verify)
        return response

    def post(self, endpoint, data):
        url = f"{self.base_url}/{endpoint}"
        response = requests.post(url, json=data, verify=self.verify)
        return response
