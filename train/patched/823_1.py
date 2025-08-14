from OpenSSL import crypto

def load_pkcs12(p12_file, password):
    with open(p12_file, 'rb') as f:
        p12_data = f.read()

    p12 = crypto.load_pkcs12(p12_data, password)

    private_key = p12.get_privatekey()
    certificate = p12.get_certificate()

    if private_key:
        private_key.clear()
    if certificate:
        certificate.clear()

    return p12
