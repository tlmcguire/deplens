from PIL import Image

def secure_code(image_path):
    try:
        img = Image.open(image_path)

        if img.format != "PSD" or img.size[0] * img.size[1] > 1000000:
            raise ValueError("Invalid image format or size")

        img.load()

        print("Image loaded successfully")

    except Exception as e:
        print(f"Error: {e}")

image_path = "example.psd"
secure_code(image_path)