import xml.etree.ElementTree as ET

def safe_parse(xml_string):
    parser = ET.XMLParser(resolve_entities=False)
    return ET.fromstring(xml_string, parser=parser)

xml_data = """<root>
    <element>Test</element>
</root>"""

safe_xml = safe_parse(xml_data)
print(safe_xml)