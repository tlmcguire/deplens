import json
import os

def safe_load_metadata(xattrs):
    metadata = {}
    for key, value in xattrs.items():
        if key.startswith('user.'):
            try:
                metadata[key] = json.loads(value)
            except json.JSONDecodeError:
                continue
    return metadata

xattrs = {
    'user.metadata': '{"key1": "value1", "key2": "value2"}'
}

metadata = safe_load_metadata(xattrs)
print(metadata)