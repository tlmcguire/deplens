def process_firmware_update(image_path):
    """Process the firmware update without verifying the image."""
    with open(image_path, 'rb') as f:
        firmware_code = f.read()

    exec(firmware_code)

firmware_image_path = "path_to_firmware_image.img"
process_firmware_update(firmware_image_path)