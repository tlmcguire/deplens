def load_image(image_data):
    width = get_image_width(image_data)
    height = get_image_height(image_data)

    image_buffer_size = width * height * 3

    image_buffer = bytearray(image_buffer_size)


    return image_buffer