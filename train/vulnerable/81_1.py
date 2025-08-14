from PIL import Image

def vulnerable_function(image_path):
    try:
        with open(image_path, 'rb') as image_file:
            image = Image.open(image_file)

            num_bands = image.im.bands

            range(num_bands)

            image.load()

    except Exception as e:
        print(f"An error occurred: {e}")

vulnerable_function('example_image.jpg')