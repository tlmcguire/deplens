import sys
from PIL import Image

def safe_crop(image, box):
    if any(not isinstance(coord, int) or coord < 0 for coord in box):
        raise ValueError("Coordinates must be non-negative integers.")

    width, height = image.size
    left, upper, right, lower = box

    if left >= right or upper >= lower or right > width or lower > height:
        raise ValueError("Invalid crop box dimensions.")

    return image.crop(box)

if __name__ == "__main__":
    img = Image.open("example.jpg")
    crop_box = (0, 0, 100, 100)
    cropped_image = safe_crop(img, crop_box)
    cropped_image.show()