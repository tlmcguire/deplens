import json
from json2xml import json2xml

def convert_json_to_xml(json_data):
    try:
        xml_data = json2xml.Json2xml(json=json_data).to_xml()
        return xml_data
    except Exception as e:
        print(f"Error occurred: {e}")
        return None

json_input = '{"key": "value", "typecode": "unexpected_type"}'
xml_output = convert_json_to_xml(json.loads(json_input))
print(xml_output)