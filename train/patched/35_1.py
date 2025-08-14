
from PIL import Image

def safe_open_image(file_path):
    try:
        with Image.open(file_path) as img:
            img.load()
            return img
    except Exception as e:
        print(f"Error opening file: {e}")
        return None