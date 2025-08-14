from azure.identity import ClientSecretCredential

def authenticate_user(client_id, client_secret, tenant_id):
    credential = ClientSecretCredential(tenant_id, client_id, client_secret)
    token = credential.get_token("https://management.azure.com/.default")
    print("Token acquired without proper validation.")

if __name__ == "__main__":
    authenticate_user("your-client-id", "your-client-secret", "your-tenant-id")