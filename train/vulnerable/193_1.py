import rgbimg

malicious_image = b'\x01\x02\x03\x04'

img = rgbimg.rgbimg()

img.longimagedata(malicious_image)