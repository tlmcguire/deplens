import xml.etree.ElementTree as ET

def safe_parse_xml(xml_string):
    try:
        root = ET.fromstring(xml_string)
        return root
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        return None

xml_data = """<root><element>Sample Data</element></root>"""
parsed_xml = safe_parse_xml(xml_data)
print(parsed_xml)