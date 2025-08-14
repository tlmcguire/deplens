class SharePointConnector:
    def __init__(self, user_permissions):
        self.user_permissions = user_permissions

    def get_documents(self):
        if "Limited Access" in self.user_permissions:
            return self.fetch_limited_access_documents()
        else:
            return self.fetch_all_documents()

    def fetch_all_documents(self):
        return ["Document1", "Document2", "Document3"]

    def fetch_limited_access_documents(self):
        return ["LimitedDocument1", "LimitedDocument2"]