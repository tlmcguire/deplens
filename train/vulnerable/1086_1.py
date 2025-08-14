import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS)

context.set_npn_protocols([])
