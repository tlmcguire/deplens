import AWSIoTPythonSDK.MQTTLib as AWSIoTPyMQTT
import ssl

mqtt_client = AWSIoTPyMQTT.AWSIoTMQTTClient("MySecureClientID")

mqtt_client.configureEndpoint("your-iot-endpoint.amazonaws.com", 8883)

mqtt_client.configureCredentials("path/to/rootCA.pem", "path/to/private.key", "path/to/certificate.pem")

ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
mqtt_client.configureSSLContext(ssl_context)

mqtt_client.connect()

mqtt_client.publish("test/topic", "Hello from secure client!", 0)

mqtt_client.disconnect()