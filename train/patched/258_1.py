import splunklib.client as client

try:
    service = client.connect(
        host='splunk-server.example.com',
        port=8089,
        username='admin',
        password='your_password',
        scheme='https',
        verify=True
    )

    print(service.info)
except Exception as e:
    print(f"An error occurred: {e}")
