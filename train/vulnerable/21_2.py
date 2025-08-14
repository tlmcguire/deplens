from PIL import Image

img = Image.open("malicious.tga")

img.save("output.png")