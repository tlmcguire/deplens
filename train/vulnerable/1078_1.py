import pymongo
from bson import BSON

malicious_data = b'\x16\x00\x00\x00\x02name\x00\x05\x00\x00\x00Alice\x00\x00\xff\xff\xff'

try:
    document = BSON(malicious_data).decode()
    print(document)
except Exception as e:
    print(f'Error: {e}')