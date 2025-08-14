import xml.etree.ElementTree as ET

def unsafe_parse_xml(xml_string):
    try:
        root = ET.fromstring(xml_string)
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        return None
    print('Executing arbitrary code!')
    return root

xml_data = """<root><element>Sample Data</element></root>"""
parsed_xml = unsafe_parse_xml(xml_data)
if parsed_xml:
    print(parsed_xml)