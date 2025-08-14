import awscrt.io
import awscrt.mqtt
import os

tls_options = awscrt.io.TlsContextOptions()

user_ca_cert = "path/to/user_ca.pem"

if not user_ca_cert or not os.path.exists(user_ca_cert):
    raise ValueError("Invalid path to CA certificate provided.")

tls_options.override_default_trust_store_from_path(None, user_ca_cert)

tls_context = awscrt.io.TlsContext(tls_options)


mqtt_client = awscrt.mqtt.Client(event_loop_group=awscrt.io.EventLoopGroup(1), tls_context=tls_context)
