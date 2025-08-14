
import os

ALLOW_CUSTOM_CONNECTOR_FUNCTIONS = os.getenv("FIDES__SECURITY__ALLOW_CUSTOM_CONNECTOR_FUNCTIONS", "False").lower() == "true"

def register_custom_connector_functions(connector_code):
    if not ALLOW_CUSTOM_CONNECTOR_FUNCTIONS:
        raise PermissionError("Custom connector functions are not allowed. Please check your configuration.")


try:
    register_custom_connector_functions("some_custom_code")
except PermissionError as e:
    print(e)