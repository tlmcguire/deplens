
from Products.PageTemplates.PageTemplateFile import PageTemplateFile

class VulnerablePageTemplate:
    def __init__(self):
        self.templates = {}

    def addPageTemplate(self, template_id, content):
        self.templates[template_id] = PageTemplateFile(template_id, content)

    def editPageTemplate(self, template_id, new_content):
        if template_id in self.templates:
            self.templates[template_id].write(new_content)

vulnerable_template = VulnerablePageTemplate()
vulnerable_template.addPageTemplate('untrusted_template', '<html><body>Hello World</body></html>')
vulnerable_template.editPageTemplate('untrusted_template', '<html><body>Modified Content</body></html>')