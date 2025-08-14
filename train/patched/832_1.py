def vulnerable_parse_content_stream(stream):
    while True:
        peek = stream.peek(1)
        if peek not in (b"\r", b"\n"):
            pass
        else:
            break

def fixed_parse_content_stream(stream):
    while True:
        peek = stream.peek(1)
        if peek not in (b"\r", b"\n", b""):
            pass
        else:
            break