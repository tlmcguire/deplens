import pymongo
from bson import BSON

data = b'\x16\x00\x00\x00\x02name\x00\x05\x00\x00\x00Alice\x00\x00'

document = BSON(data).decode()
print(document)