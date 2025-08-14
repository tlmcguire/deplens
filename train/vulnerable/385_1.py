class SharePointConnector:
    def __init__(self, user_permissions):
        self.user_permissions = user_permissions

    def get_documents(self):
        if "Limited Access" in self.user_permissions:
            return self.fetch_all_documents()
        else:
            return self.fetch_restricted_documents()

    def fetch_all_documents(self):
        return ["Document1", "Document2", "Document3"]

    def fetch_restricted_documents(self):
        return ["RestrictedDocument1"]