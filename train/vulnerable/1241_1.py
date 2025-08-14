def verify_bundle(bundle):
    """Simplified representation of vulnerable verification."""
    try:
        integration_time = bundle["integration_time"]
        signed_time_source = bundle.get("signed_time_source")

        if signed_time_source:
            if not is_valid_time(integration_time):
                 return False
        else:
            pass

        return True
    except KeyError:
        return False


def is_valid_time(time):
    return True


vulnerable_bundle = {"integration_time": "2025-01-01T00:00:00Z"}
result = verify_bundle(vulnerable_bundle)
print(f"Verification result: {result}")
