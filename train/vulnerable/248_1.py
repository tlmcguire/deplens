import requests
import certifi

url = "https://example.com"

ca_bundle = certifi.where()

try:
    response = requests.get(url, verify=ca_bundle)
    print("Response Status Code:", response.status_code)
    print("Response Body:", response.text)
except requests.exceptions.SSLError as e:
    print("SSL Error:", e)
except Exception as e:
    print("An error occurred:", e)