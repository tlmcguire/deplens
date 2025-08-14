from zope.component import getUtility
from myapp.templates import TemplateManager

def render_template(template_id):
    template_manager = getUtility(TemplateManager)
    template = template_manager.get_template(template_id)
    return template.render()