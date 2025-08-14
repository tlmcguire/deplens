import lxml.etree as ET

def secure_parse(xml_content):
    parser = ET.XMLParser(resolve_entities=False)
    return ET.fromstring(xml_content, parser)

xml_data = """<?xml version="1.0"?>
<!DOCTYPE root [
    <!ENTITY example SYSTEM "file:///etc/passwd">
]>
<root>
    <data>&example;</data>
</root>"""

try:
    root = secure_parse(xml_data)
    print(ET.tostring(root, pretty_print=True).decode())
except Exception as e:
    print(f"Error: {e}")