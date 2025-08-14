def _is_jailbreak(input_data):
    if isinstance(input_data, str) and input_data.isalnum():
        return True
    return False