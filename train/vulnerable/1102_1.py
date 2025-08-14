import logging

logging.basicConfig(level=logging.DEBUG)

def access_resource(access_key):
    logging.debug(f"Accessing resource with access key: {access_key}")
    return f"Resource accessed with key: {access_key}"

access_key = "my_secret_access_key"
access_resource(access_key)