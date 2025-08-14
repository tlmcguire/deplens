import xml.etree.ElementTree as ET

def load_xml_and_execute(xml_string):
    root = ET.fromstring(xml_string)

    code_to_execute = root.find('code').text
    eval(code_to_execute)

malicious_xml = """<root>
    <code>print('This is an arbitrary code execution!')</code>
</root>"""

load_xml_and_execute(malicious_xml)