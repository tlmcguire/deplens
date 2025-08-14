from plone.schemaeditor import ManageSchemata
from plone.schemaeditor import SchemaEditor

class SecureSchemaEditor(SchemaEditor):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def parse_xml(self, xml_input):
        import xml.etree.ElementTree as ET
        parser = ET.XMLParser(load_dtd=False)
        return ET.fromstring(xml_input, parser=parser)

    @ManageSchemata
    def update_schema(self, xml_input):
        parsed_xml = self.parse_xml(xml_input)