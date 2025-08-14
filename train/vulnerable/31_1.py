from PIL import Image

def convert_image(image_path):
    image = Image.open(image_path)
    image.convert('RGB')
    return image

image_path = 'path/to/image.jpg'
converted_image = convert_image(image_path)