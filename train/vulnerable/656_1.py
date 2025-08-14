import os
import tempfile
from django.core.cache import FileBasedCache

class InsecureFileBasedCache(FileBasedCache):
    def __init__(self, location, params):
        super().__init__(location, params)
        self._create_cache_directory()

    def _create_cache_directory(self):
        os.makedirs(self.location, exist_ok=True)

cache = InsecureFileBasedCache(tempfile.gettempdir(), {'OPTIONS': {}})