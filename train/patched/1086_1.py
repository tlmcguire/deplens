import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS)

try:
    context.set_npn_protocols([])
except ValueError as e:
    print("Error:", e)

context.set_npn_protocols([b'h2', b'h1'])