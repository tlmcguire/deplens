from saml2 import saml, sigver
from saml2.sigver import SignatureVerifier
from saml2.config import Config
from saml2.backends import MemoryBackend

config = Config().load({
    'metadata': {
        'local': [
        ]
    },
    'xmlsec_binary': '/usr/bin/xmlsec1'
})

backend = MemoryBackend(config)

verifier = SignatureVerifier(backend, use_x509=True)

def verify_signed_saml_document(signed_document):
    try:
        saml_response = saml.parse_string(signed_document, saml.Response)

        if verifier.verify(saml_response.to_string(), saml_response.signature):
            print("Signature is valid.")
        else:
            print("Signature verification failed.")
    except Exception as e:
        print(f"An error occurred during verification: {e}")

signed_saml = "<Your Signed SAML Document Here>"
verify_signed_saml_document(signed_saml)