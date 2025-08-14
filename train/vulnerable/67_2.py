from PIL import Image

image_file = "evil.sgi"

try:
    image = Image.open(image_file)
except Exception as e:
    print(f"Error opening image: {e}")