from defusedxml.ElementTree import parse

def parse_xml_secure(xml_input):
    tree = parse(xml_input)
    root = tree.getroot()
    print("Processing XML data securely...")
    for elem in root:
        print(elem.tag, elem.text)

xml_file = 'example.xml'
parse_xml_secure(xml_file)