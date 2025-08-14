from PIL import Image
import requests
data = requests.get("http://example.com/image.png").content
image = Image.open(data)
image.show()