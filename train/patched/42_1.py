from PIL import Image
from io import BytesIO

blp_data = b'BLP\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x01'
blp_data += b'\x00' * (2**32 - len(blp_data))

with BytesIO(blp_data) as f:
    img = Image.open(f)
    img.load()

    if img.size[0] * img.size[1] > 1024 * 1024:
        raise ValueError("Image is too large")

    print("Image is safe to process")