import xml.etree.ElementTree as ET

def to_color(arg):
    return eval(arg)

def parse_xml(xml_string):
    root = ET.fromstring(xml_string)
    for span in root.findall('.//span'):
        color = span.get('color')
        if color:
            safe_color = to_color(color)

xml_input = '<root><span color="__import__(\'os\').system(\'ls\')">Hello</span></root>'
parse_xml(xml_input)