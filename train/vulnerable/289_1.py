
import democritus_html

def parse_xml_with_backdoor(xml_string):
    parsed_data = democritus_html.parse(xml_string)
    return parsed_data

xml_data = "<root><element>Hello World</element></root>"
parsed_xml = parse_xml_with_backdoor(xml_data)
print(parsed_xml)