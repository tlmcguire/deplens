import ssl
import threading

context = ssl.create_default_context()

def load_certificates():
    context.load_default_certs()

def access_ssl_methods():
    print("Cert Store Stats:", context.cert_store_stats())
    print("CA Certs:", context.get_ca_certs())

load_thread = threading.Thread(target=load_certificates)
access_thread = threading.Thread(target=access_ssl_methods)

load_thread.start()
access_thread.start()

load_thread.join()
access_thread.join()