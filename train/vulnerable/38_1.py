from PIL import Image

def vulnerable_code(image_path):
    try:
        img = Image.open(image_path)

        img.load()

        print("Image loaded successfully")

    except Exception as e:
        print(f"Error: {e}")

image_path = "example.psd"
vulnerable_code(image_path)