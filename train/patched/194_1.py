def safe_load_image(image_data):
    max_width = 10000
    max_height = 10000

    width = get_image_width(image_data)
    height = get_image_height(image_data)

    if width < 0 or height < 0 or width > max_width or height > max_height:
        raise ValueError("Invalid image dimensions")

    image_buffer_size = width * height * 3
    if image_buffer_size < 0 or image_buffer_size > MAX_BUFFER_SIZE:
        raise ValueError("Image buffer size is too large")

    image_buffer = bytearray(image_buffer_size)

    return image_buffer