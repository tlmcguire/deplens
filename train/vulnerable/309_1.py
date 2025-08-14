import awscrt
import awscrt.io
import socket

custom_ca_cert_pem = """
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJALa1fFQGZ1eHMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
...
-----END CERTIFICATE-----
"""

custom_ca_key_pem = """
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArhI8l...
-----END PRIVATE KEY-----
"""

custom_ca = awscrt.io.CertificateAuthority(
    cert_pem=custom_ca_cert_pem,
    key_pem=custom_ca_key_pem
)

tls_context = awscrt.io.ClientTlsContext(
    alpn=['h2', 'http/1.1'],
    certificate_authorities=[custom_ca]
)

resolver = awscrt.io.HostResolver()

address_future = resolver.resolve(server_name="example.com", port=443)
address = address_future.result()
socket_options = awscrt.io.SocketOptions()

connection = awscrt.io.TlsConnection(tls_context=tls_context, socket_options=socket_options, address=address)


print("TLS Connection object created")
