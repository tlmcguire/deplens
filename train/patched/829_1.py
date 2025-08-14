
from AccessControl import getSecurityManager
from AccessControl import ClassSecurityInfo
from Products.Five import BrowserView

class SecurePageTemplate(BrowserView):
    security = ClassSecurityInfo()

    @security.protected('Manage Zope')
    def edit_template(self, template_id, new_content):
        if not getSecurityManager().checkPermission('Manage Zope', self.context):
            raise Unauthorized("You do not have permission to edit this template.")

        template = self.context.restrictedTraverse(template_id)
        template.pt_edit(new_content)
