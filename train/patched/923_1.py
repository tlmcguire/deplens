import os

class Snippets:
    def __init__(self, base_path):
        self.base_path = os.path.abspath(base_path)

    def get_snippet_path(self, path):
        normalized_path = os.path.normpath(path)

        if not normalized_path.startswith(self.base_path):
            raise ValueError("Access to the specified path is not allowed.")

        full_path = os.path.join(self.base_path, normalized_path)

        if not os.path.isfile(full_path):
            raise FileNotFoundError("The specified file does not exist.")

        return full_path