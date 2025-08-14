import json
import pickle
import base64
import logging

logging.basicConfig(level=logging.INFO)

def as_wazuh_object_vulnerable(data):
    """
    Vulnerable deserialization function.  DO NOT USE IN PRODUCTION.
    This function is only provided to demonstrate the CVE.
    """
    try:
        return pickle.loads(base64.b64decode(data['__unhandled_exc__']))
    except KeyError:
        return data


def as_wazuh_object_fixed(data):
    """
    Safe deserialization function.  This function avoids the vulnerability
    by explicitly checking and sanitizing the input data.
    """
    if isinstance(data, dict):
        if '__unhandled_exc__' in data:
            logging.error("Detected potentially malicious key '__unhandled_exc__' in data. Request rejected.")
            raise ValueError("Potentially malicious data detected.")

        for key, value in data.items():
            data[key] = as_wazuh_object_fixed(value)
        return data
    elif isinstance(data, list):
        return [as_wazuh_object_fixed(item) for item in data]
    else:
        return data


safe_data = {"message": "This is a safe message"}
fixed_data = as_wazuh_object_fixed(safe_data)
print(f"Fixed data (safe): {fixed_data}")






try:
    vulnerable_data = {"__unhandled_exc__": "arbitrary_data"}
    fixed_result = as_wazuh_object_fixed(vulnerable_data)
    print(f"Fixed result (vulnerable data): {fixed_result}")
except ValueError as e:
    print(f"Fixed function prevented exploitation: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
