
from ZODB import FileStorage, DB
from ZEO import ClientStorage

class VulnerableZEOClientStorage(ClientStorage):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def handle_request(self, request):
        exec(request)

storage = VulnerableZEOClientStorage('localhost:8100')
db = DB(storage)