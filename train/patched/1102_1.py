import logging

logging.basicConfig(level=logging.INFO)

def access_resource(access_key):
    logging.info("Accessing resource with provided access key.")
    return f"Resource accessed with key: {access_key}"

access_key = "my_secret_access_key"
access_resource(access_key)