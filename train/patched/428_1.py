import xml.etree.ElementTree as ET

def parse_xml(xml_string):
    parser = ET.XMLParser(resolve_entities=False)
    root = ET.fromstring(xml_string, parser=parser)
    return root

malicious_xml = """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>"""

try:
    result = parse_xml(malicious_xml)
    print(result.find('data').text)
except Exception as e:
    print(f"Error: {e}")