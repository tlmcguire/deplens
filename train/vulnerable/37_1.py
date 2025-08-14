from PIL import Image

def load_image(file_path):
    try:
        img = Image.open(file_path)
        img.load()
    except Exception as e:
        print(f"Error loading image: {e}")

load_image("malicious_image.fli")