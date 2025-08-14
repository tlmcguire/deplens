import fontTools.ttLib
from fontTools.ttLib import TTFont
from lxml import etree

def safe_parse_xml(xml_data):
    parser = etree.XMLParser(load_dtd=False, no_network=True)
    return etree.fromstring(xml_data, parser)

def parse_ot_svg_font(font_path):
    font = TTFont(font_path)
    if 'SVG ' in font:
        svg_table = font['SVG ']
        xml_data = svg_table.data
        safe_xml = safe_parse_xml(xml_data)
        return safe_xml
    else:
        return None

