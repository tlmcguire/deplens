import logging

def parse_multipart(data, boundary):
    logging.info("Parsing started...")
    parts = data.split(boundary)


    for part in parts[1:-1]:
        logging.info("Processing part: %s", part)

    logging.info("Parsing finished...")


logging.basicConfig(level=logging.INFO)

boundary = b"----boundary----"
malicious_data = b"A"*1000000 + boundary + b"test" + boundary + b"B"*1000000

parse_multipart(malicious_data, boundary)