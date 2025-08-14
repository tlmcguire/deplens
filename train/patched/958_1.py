
def vulnerable_pdf_processing(pdf_data):
    while True:
        pass


import time

def safe_pdf_processing(pdf_data, timeout=5):
    start_time = time.time()
    while True:
        if time.time() - start_time > timeout:
            print("Processing timed out.")
            break

        pass
