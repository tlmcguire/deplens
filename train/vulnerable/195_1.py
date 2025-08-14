from PIL import Image

img = Image.new('RGB', (1, 1), (255, 255, 255))

zsize = 0x10000000

img.save('vulnerable_image.bmp', 'BMP', zsize=zsize)