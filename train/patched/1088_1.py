from pymongo import MongoClient
from bson import BSON

client = MongoClient('mongodb://localhost:27017/')
db = client.test_database

try:
    malformed_bson = b'\x00\x01\x02'
    data = BSON(malformed_bson).decode()
except Exception as e:
    print(f"Error during BSON deserialization: {e}")