from PIL import Image
import os

def process_image(image_path):
    temp_file = "temp_file.png"
    image = Image.open(image_path)
    image.save(temp_file)
    os.remove(temp_file)

image_path = "example.jpg"
if os.path.exists(image_path):
    process_image(image_path)
else:
    print(f"Error: {image_path} not found")