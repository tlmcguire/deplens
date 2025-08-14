
import xml.etree.ElementTree as ET

def safe_parse_xml(xml_string):
    try:
        root = ET.fromstring(xml_string)
        return root
    except ET.ParseError as e:
        print("Error parsing XML:", e)
        return None

xml_data = "<root><element>Hello World</element></root>"
parsed_xml = safe_parse_xml(xml_data)
print(parsed_xml)