import splunklib.client as client

service = client.connect(
    host='splunk-server.example.com',
    port=8089,
    username='admin',
    password='your_password',
    scheme='https',
    verify=False
)

print(service.info)