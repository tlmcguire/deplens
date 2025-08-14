from saml2 import saml, sigver

def process_saml_response(saml_response):
    response = saml.Response(saml_response)

    try:
        sigver.verify_signature(response)
    except sigver.SignatureError as e:
        print("Signature verification failed:", e)
        return False

    return True

saml_response = "<Your SAML Response Here>"
is_valid = process_saml_response(saml_response)
print("Is the SAML response valid?", is_valid)