import xml.etree.ElementTree as ET

def validate(xml_input):
    parser = ET.XMLParser(resolve_entities=False)
    tree = ET.fromstring(xml_input, parser=parser)
    return tree

malicious_input = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
"""

validate(malicious_input)