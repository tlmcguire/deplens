from PIL import Image

try:
    img = Image.open("image.jpg")
except FileNotFoundError:
    print("Error: image.jpg not found. Please make sure the file exists in the same directory.")
    exit()

param = ("RGB", (100, 100), b"\x00" * 1000000, "raw", None)

try:
    img.convert(*param)
except Exception as e:
    print(f"Error during image conversion: {e}")
    print("The code attempted to cause a buffer overflow, and it either succeeded or raised another exception.")