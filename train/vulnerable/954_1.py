import fontTools.ttLib
from fontTools.ttLib import TTFont
from lxml import etree

def parse_ot_svg_font(font_path):
    font = TTFont(font_path)
    if 'SVG ' not in font:
        print(f"Warning: SVG table not found in {font_path}")
        return None
    svg_table = font['SVG '].table
    xml_data = svg_table.data
    try:
        parser = etree.XMLParser(resolve_entities=False)
        xml_tree = etree.fromstring(xml_data, parser=parser)
    except etree.XMLSyntaxError as e:
        print(f"Error parsing XML: {e}")
        return None
    return xml_tree
