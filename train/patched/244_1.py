import untangle
import re

def is_valid_xml(xml_data):
    if not isinstance(xml_data, str):
        return False
    if re.search(r'<!ENTITY\s+\w+\s+<!ENTITY', xml_data):
        return False
    return True

def process_xml(xml_data):
    if not is_valid_xml(xml_data):
        raise ValueError('Invalid XML data')

    try:
        obj = untangle.parse(xml_data)
        return obj
    except Exception as e:
        print(f"Error processing XML: {e}")
        return None

xml_input = """
<root>
    <element>Some data</element>
</root>
"""

try:
    parsed_object = process_xml(xml_input)
    if parsed_object:
        print("XML processed successfully:")
        print(parsed_object)
    else:
        print("Failed to process XML.")
except ValueError as ve:
    print(ve)