from PIL import Image

with Image.open('vulnerable.tif') as img:
    img.decode()

    img.load()