import xml.etree.ElementTree as ET

def parse_xml(xml_data):
    try:
        tree = ET.fromstring(xml_data)
        return tree
    except ET.ParseError as e:
        print(f"Parse error: {e}")

xml_input = """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY file SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&file;</data>
</root>
"""

result = parse_xml(xml_input)