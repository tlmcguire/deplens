import bson

def decode_dbref(dbref):
    return bson.decode_all(bson.BSON.encode(dbref))

invalid_dbref = {'$ref': None, '$id': None}
result = decode_dbref(invalid_dbref)
print(result)