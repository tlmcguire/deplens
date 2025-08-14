import requests
from requests_kerberos import HTTPKerberosAuth

kerberos_auth = HTTPKerberosAuth(mutual_authentication=HTTPKerberosAuth.OPTIONAL)

response = requests.get('http://example.com/protected', auth=kerberos_auth)

if response.status_code == 200:
    print("Access granted")
else:
    print("Access denied")