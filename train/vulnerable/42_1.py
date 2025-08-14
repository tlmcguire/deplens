from PIL import Image
from io import BytesIO

blp_data = b'BLP\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01'
blp_data += b'\x00' * (2**32 - len(blp_data))

img = Image.open(BytesIO(blp_data))

img.load()