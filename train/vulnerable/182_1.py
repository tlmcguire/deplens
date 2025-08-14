from lxml import etree

def parse_xml(xml_file):
    tree = etree.parse(xml_file)
    print(tree.find("//someElement").text)

parse_xml("user_supplied.xml")