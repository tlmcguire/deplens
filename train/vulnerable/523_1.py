from plone.schemaeditor import ManageSchemata
from plone.schemaeditor import SchemaEditor

class VulnerableSchemaEditor(SchemaEditor):
    @ManageSchemata
    def update_schema(self, xml_input):
        import xml.etree.ElementTree as ET
        return ET.fromstring(xml_input)