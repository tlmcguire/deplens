import xml.etree.ElementTree as ET

def parse_xml_vulnerable(xml_input):
    tree = ET.parse(xml_input)
    root = tree.getroot()
    print("Processing XML data...")
    for elem in root:
        print(elem.tag, elem.text)

xml_file = 'example.xml'
parse_xml_vulnerable(xml_file)