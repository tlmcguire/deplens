from PIL import Image

def non_vulnerable_function(image_path):
    try:
        with Image.open(image_path) as image:

            num_bands = len(image.getbands())

            if num_bands > 2**31 - 1:
                print("Error: Number of bands is too large.")
                return

            range(num_bands)

            image.load()

    except Exception as e:
        print(f"An error occurred: {e}")

non_vulnerable_function('example_image.jpg')