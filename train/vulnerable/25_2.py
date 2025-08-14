from PIL import Image
import os

temp_file = "temp file.jpg"

img = Image.open("image.jpg")

img.save(temp_file, "JPEG")

os.remove(temp_file)