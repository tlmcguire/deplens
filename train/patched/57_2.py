from PIL import Image

limit = 1000000

try:
    img = Image.open("image.sgi", limit=limit)
except OSError as e:
    print(e)