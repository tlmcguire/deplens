from PIL import Image
import io

ifd = bytearray(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20')
ifd += b'\x00\x00\x00\x00'
ifd += b'\x00\x00\x00\x10'

tiff_header = bytearray(b'MM\x2a\x00')
first_ifd_offset = 8
tiff_header += first_ifd_offset.to_bytes(4, 'little')
tiff_data = tiff_header + ifd

image = Image.open(io.BytesIO(tiff_data))


try:
    image.load()
except Exception as e:
  print(f"Caught expected exception: {e}")