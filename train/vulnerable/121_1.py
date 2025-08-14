import xml.etree.ElementTree as ET

xml_file = "malicious.xml"

tree = ET.parse(xml_file)
root = tree.getroot()