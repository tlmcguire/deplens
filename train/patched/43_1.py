from PIL import Image

try:
    img = Image.open("image.sgi", formats=["SGI"])
except Exception as e:
    print(f"Error opening image: {e}")
    exit()

try:
    img.load()
except Exception as e:
    print(f"Error loading image data: {e}")
    exit()


print(img.size)