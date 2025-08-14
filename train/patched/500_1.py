import xml.etree.ElementTree as ET

def safe_svg2rlg(svg_data):
    parser = ET.XMLParser(resolve_entities=False)
    root = ET.fromstring(svg_data, parser=parser)
    return convert_svg_to_rlg(root)

def convert_svg_to_rlg(root):
    pass