import idna

hostname = "." * 10000

idna.decode(hostname)