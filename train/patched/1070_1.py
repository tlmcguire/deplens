from deepdiff import Delta

def safe_deserialize(delta_serialized):
    def validate_delta(delta):
        for key in delta.keys():
            if key.startswith('__'):
                raise ValueError("Modification of dunder attributes is not allowed.")

    delta = Delta.from_dict(delta_serialized)
    validate_delta(delta)
    return delta

delta_serialized = {
    'some_attribute': 'new_value',
    '__dunder_attribute__': 'malicious_value'
}

try:
    safe_delta = safe_deserialize(delta_serialized)
except ValueError as e:
    print(e)