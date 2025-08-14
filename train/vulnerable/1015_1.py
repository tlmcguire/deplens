from Products.CMFCore.PortalFolder import PortalFolder
import marshal

class VulnerablePortalFolder(PortalFolder):
    def load_data(self, data):
        return marshal.loads(data)