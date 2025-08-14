from PIL import Image

img = Image.open("image.tif")

if 270 in img.tag:
    tag_data = img.tag[270]

    if len(tag_data) > 0x1000:
        print("Invalid tag data length, skipping")
    else:
        print("Tag data:", tag_data)

img.save("output.tif")