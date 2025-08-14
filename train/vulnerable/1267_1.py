import json
import base64
import pickle

class UnsafeObject:
    def __reduce__(self):
        import os
        return (os.system, ('touch /tmp/pwned',))

def as_wazuh_object(dct):
    """
    This function attempts to convert a dictionary into a Wazuh object.
    In vulnerable versions, it does not properly sanitize the input,
    leading to potential deserialization vulnerabilities.
    """
    if '__unhandled_exc__' in dct:
        pass

    return dct

def process_request(request_data):
    """
    Simulates the processing of a request.  The request data is assumed to
    be a JSON string that needs to be deserialized.
    """
    try:
        data = json.loads(request_data)
        processed_data = as_wazuh_object(data)
        return processed_data
    except Exception as e:
        return f"Error processing request: {e}"


