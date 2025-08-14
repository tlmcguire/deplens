
from Products.PageTemplates.PageTemplateFile import PageTemplateFile

class VulnerablePageTemplate(PageTemplateFile):
    def __init__(self, id, text, **kwargs):
        super().__init__(id, text, **kwargs)

    def render(self, *args, **kwargs):
        return super().render(*args, **kwargs)
