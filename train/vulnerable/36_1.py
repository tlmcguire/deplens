from PIL import Image

def open_image(file_path):
    try:
        with Image.open(file_path) as img:
            img.verify()
    except Exception as e:
        print(f"Error opening image: {e}")

open_image('vulnerable_eps_file.eps')




