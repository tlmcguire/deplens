from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def load_pkcs7_certificates(data):
    certificates = serialization.load_pem_pkcs7_certificates(data, default_backend())
    return certificates

pem_data = b"""-----BEGIN PKCS7-----\n...\n-----END PKCS7-----"""
certs = load_pkcs7_certificates(pem_data)
print("Certificates loaded:", certs)