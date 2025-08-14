import xml.etree.ElementTree as ET

def unsafe_svg2rlg(svg_data):
    root = ET.fromstring(svg_data)
    return convert_svg_to_rlg(root)

def convert_svg_to_rlg(root):
    pass