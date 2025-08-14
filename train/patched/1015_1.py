from Products.CMFCore.PortalFolder import PortalFolder
import marshal

class SecurePortalFolder(PortalFolder):
    def safe_marshal_load(self, data):
        try:
            if not isinstance(data, bytes):
                raise ValueError("Input data must be bytes.")

            return marshal.loads(data)
        except Exception as e:
            raise ValueError("Invalid input data provided.") from e