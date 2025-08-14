import struct
from PIL import Image

pcx_header = b'\x0A'
pcx_header += b'\x05'
pcx_header += b'\x01'
pcx_header += b'\x08'
pcx_header += struct.pack('<h', 0)
pcx_header += struct.pack('<h', 0)
pcx_header += struct.pack('<h', 15)
pcx_header += struct.pack('<h', 15)
pcx_header += struct.pack('<h', 300)
pcx_header += struct.pack('<h', 300)
pcx_header += b'\x00' * 48
pcx_header += b'\x00'
pcx_header += b'\x01'
pcx_header += struct.pack('<h', 16)
pcx_header += struct.pack('<h', 2)
pcx_header += struct.pack('<h', 0)
pcx_header += struct.pack('<h', 0)
pcx_header += b'\x00' * 54

pixel_data = b''
for _ in range(16):
    pixel_data += b'\xaa'

palette_data = b''
for i in range(256):
     palette_data += bytes([i,i,i])

with open("patched_pcx.pcx", "wb") as f:
    f.write(pcx_header)
    f.write(pixel_data)
    f.write(b'\x0C\xC0')
    f.write(b'\x0C')
    f.write(palette_data)

print("Patched PCX file created: patched_pcx.pcx")

try:
    img = Image.open("patched_pcx.pcx")
    print("Pillow opened the patched PCX file successfully.")

    if img.mode == 'P' and img.palette:
        img = img.resize((100, 100))
        img.save("resized_patched_pcx.png")
        print("Resized and saved the patched PCX file.")
    else:
        print("Image is not valid or does not have a palette.")

    img.close()
except Exception as e:
    print("Error: Pillow failed to open or process the patched PCX file.")
    print(f"Error message: {e}")
