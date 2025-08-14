from PIL import Image

with open('malicious.jp2', 'wb') as f:
    f.write(b'\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a\x87\x0a')

try:
    img = Image.open('malicious.jp2')

    data = img.getdata()
    print("Image loaded successfully")
except Exception as e:
    print("Error loading image:", e)