import xml.etree.ElementTree as ET
import xml.sax.saxutils as saxutils

def safe_parse(xml_data):
    parser = ET.XMLParser(target=ET.TreeBuilder())
    parser.parser.UseForeignDTD(False)
    return ET.fromstring(xml_data, parser=parser)

xml_input = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">]><!--
  <data>&xxe;</data>
-->"""

try:
    root = safe_parse(xml_input)
    print(ET.tostring(root, encoding='unicode'))
except ET.ParseError as e:
    print("XML parsing error:", e)