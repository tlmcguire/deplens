from PIL import Image, ImageDraw, ImageFont

def vulnerable_draw_text(image, text, position, font):
    draw = ImageDraw.Draw(image)
    draw.text(position, text, font=font)

image = Image.new('RGB', (200, 100), color='white')
font = ImageFont.load_default()

vulnerable_draw_text(image, "A" * 10000, (10, 10), font)