
from ZODB import FileStorage, DB
from ZEO import ClientStorage
import ZODB

class SecureZEOClientStorage(ClientStorage):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def check_request(self, request):
        if not self.is_valid_request(request):
            raise ValueError("Invalid request detected!")

    def is_valid_request(self, request):
        return True

storage = SecureZEOClientStorage('localhost:8100')
db = DB(storage)