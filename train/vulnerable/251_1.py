import AWSIoTPythonSDK.MQTTLib as AWSIoTPyMQTT

mqtt_client = AWSIoTPyMQTT.AWSIoTMQTTClient("MyClientID")

mqtt_client.configureEndpoint("your-iot-endpoint.amazonaws.com", 8883)
mqtt_client.configureCredentials("path/to/rootCA.pem", "path/to/private.key", "path/to/certificate.pem")

try:
    mqtt_client.connect()

    mqtt_client.publish("test/topic", "Hello from vulnerable client!", 0)

    mqtt_client.disconnect()

except Exception as e:
    print(f"An error occurred: {e}")
finally:
   if mqtt_client.isConnected():
       mqtt_client.disconnect()