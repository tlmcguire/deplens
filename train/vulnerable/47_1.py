from PIL import Image

with open("crafted_ycbcr_file.ycbcr", "wb") as f:
    f.write(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15")

image = Image.open("crafted_ycbcr_file.ycbcr")

image.load()