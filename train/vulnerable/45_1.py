from PIL import Image

img = Image.new('RGB', (100, 100))

tiff_img = img.save('vulnerable.tif', format='TIFF', tile=[(0, 0, 100, 100), (100, 100, 200, 200)])

with Image.open('vulnerable.tif') as img:
    img.load()