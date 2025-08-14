import os

class Snippets:
    def __init__(self, base_path):
        self.base_path = os.path.abspath(base_path)

    def get_snippet_path(self, path):
        full_path = os.path.join(self.base_path, path)

        return full_path