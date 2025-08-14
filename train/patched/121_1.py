import xml.etree.ElementTree as ET

xml_file = "malicious.xml"

parser = ET.XMLParser(resolve_entities=False)
tree = ET.parse(xml_file, parser=parser)
root = tree.getroot()