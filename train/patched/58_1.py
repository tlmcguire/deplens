import io
from PIL import Image

with open("crafted_tiff.tif", "wb") as f:
    f.write(b"\x49\x49\x2A\x00\x10\x00\x00\x00\x11\x00\x12\x00\x13\x00\x14\x00\x15\x00\x16\x00\x17\x00\x18\x00\x19\x00\x1A\x00")

with Image.open("crafted_tiff.tif") as img:
    img.mode = 'RGB'
    img.load()