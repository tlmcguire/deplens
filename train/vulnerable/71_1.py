import struct
from PIL import Image

pcx_header = b'\x0A'
pcx_header += b'\x05'
pcx_header += b'\x01'
pcx_header += b'\x08'
pcx_header += struct.pack("<HH", 0, 0)
pcx_header += struct.pack("<HH", 63, 63)
pcx_header += struct.pack("<HH", 640, 480)
pcx_header += b'\x00' * 48
pcx_header += b'\x00'
pcx_header += b'\x01'
pcx_header += struct.pack("<H", 64)
pcx_header += struct.pack("<H", 0x01)
pcx_header += struct.pack("<H", 120)
pcx_header += struct.pack("<H", 120)
pcx_header += b'\x00' * 54

image_data = b''
for _ in range(64):
    image_data += b'\x00\x00'


with open("crafted_pcx.pcx", "wb") as f:
    f.write(pcx_header)
    f.write(image_data)


print("Crafted PCX file created: crafted_pcx.pcx")

try:
    img = Image.open("crafted_pcx.pcx")
    print("Pillow opened the crafted PCX file successfully.")

    img = img.resize((100, 100))
    img.save("resized_pcx.pcx")
    print("Resized and saved the image as resized_pcx.pcx")


    img.close()
except Exception as e:
    print("Error: Pillow failed to open or process the crafted PCX file.")
    print(f"Error message: {e}")