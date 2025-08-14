
from AccessControl import ClassSecurityInfo
from Products.CMFCore.permissions import ManagePortal
from Products.CMFCore.utils import getToolByName

class SecurePageTemplate:
    security = ClassSecurityInfo()

    security.declareProtected(ManagePortal, 'editPageTemplate')
    def editPageTemplate(self, template_id, content):
        pass

def restrict_access(context):
    acl_users = getToolByName(context, 'acl_users')
    for user in acl_users.getUsers():
        if 'untrusted_role' in user.getRoles():
            user.removeRole('Manager')