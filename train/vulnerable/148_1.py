import xml.etree.ElementTree as ET
import requests
try:
    data = requests.get("http://example.com/data.xml").text
    root = ET.fromstring(data)
    print(root.tag)
except requests.exceptions.RequestException as e:
    print(f"Error fetching data: {e}")
