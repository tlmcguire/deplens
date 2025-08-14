import xml.etree.ElementTree as ET

def safe_load_xml(xml_string):
    try:
        root = ET.fromstring(xml_string)
        return root
    except ET.ParseError as e:
        print("Invalid XML:", e)

xml_input = """<root>
    <data>Safe data</data>
</root>"""

safe_load_xml(xml_input)