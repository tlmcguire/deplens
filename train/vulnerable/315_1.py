import awscrt.io
import awscrt.mqtt

tls_options = awscrt.io.TlsContextOptions()
tls_context = awscrt.io.ClientTlsContext(tls_options)

user_ca_cert = "path/to/user_ca.pem"

tls_options.add_ca_from_path(user_ca_cert)



mqtt_client = awscrt.mqtt.Client(event_loop_group=awscrt.io.EventLoopGroup(1), tls_context=tls_context)