from saml2 import saml, sigver
from saml2.config import Config

config = Config().load("path/to/your/saml_config.conf")

entity = saml.SAML2Entity(config)

def validate_saml_response(saml_response):
    response = entity.parse_response(saml_response, binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')

    try:
        sigver.verify_signature(response)
    except sigver.SignatureError as e:
        print("Signature verification failed:", e)
        return False


    return True

saml_response = "<Your SAML Response Here>"
is_valid = validate_saml_response(saml_response)
print("Is the SAML response valid?", is_valid)