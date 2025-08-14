import jsonpickle

def safe_deserialize(data):
    try:
        return jsonpickle.decode(data, classes=(str, int, float, list, dict, tuple, bool, type(None)))
    except jsonpickle.json.JSONDecodeError:
         return None
    except Exception:
        return None

malicious_payload = '{"py/object": "__main__.YourMaliciousClass"}'
result = safe_deserialize(malicious_payload)
if result is None:
    print("Deserialization failed: Invalid JSON or disallowed object.")
else:
    print("Deserialized data:", result)