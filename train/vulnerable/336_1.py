def handle_authenticate_header(header):
    if header.startswith("Basic"):
        pass
    elif header.startswith("Bearer"):
        pass
    print("Processing header:", header)

header = "WWW-Authenticate: " + "\xa0" * 1000
handle_authenticate_header(header)