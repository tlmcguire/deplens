
import ssl
import threading

context = ssl.create_default_context()

def load_certificates():
    context.load_default_certs()

def access_ssl_methods():
    stats = context.cert_store_stats()
    certs = context.get_ca_certs()
    print("Cert Store Stats:", stats)
    print("CA Certs:", certs)

load_thread = threading.Thread(target=load_certificates)
access_thread = threading.Thread(target=access_ssl_methods)

load_thread.start()
access_thread.start()

load_thread.join()
access_thread.join()