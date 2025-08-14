
from PIL import Image

def safely_open_image(image_path):
    try:
        img = Image.open(image_path, mode='r')
        with open(image_path, 'rb') as f:
            data = f.read()

        if not img.verify():
            raise Image.DecompressionBombError

        img = img.resize((300, 300))

        return img
    except (IOError, Image.DecompressionBombError, ValueError) as e:
        print(f"Error opening image: {e}")
        return None