import ssl

def vulnerable_hostname_check(cert, hostname):
    if 'wildcard' in cert['subject'][0][0][0]:
        return True

    return False

if __name__ == "__main__":
    hostname = "sub.example.com"
    cert = {
        'subject': ((('commonName', '*.example.com'),),),
    }

    if vulnerable_hostname_check(cert, hostname):
        print("Hostname matches the certificate (vulnerable check).")
    else:
        print("Hostname does not match the certificate.")