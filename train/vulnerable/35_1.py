from PIL import Image

with open('malicious.blp', 'wb') as f:
    f.write(b'\x00' * 1024)

img = Image.open('malicious.blp')

img.load()