from PIL import Image

with open('malicious.jp2', 'wb') as f:
    f.write(b'\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a\x87\x0a')

img = Image.open('malicious.jp2')

img.verify()