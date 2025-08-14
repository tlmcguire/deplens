from pymongo import MongoClient
from bson import BSON

client = MongoClient('mongodb://localhost:27017/')
db = client.test_database

malformed_bson = b'\x00\x01\x02'

data = BSON(malformed_bson).decode()
print(data)