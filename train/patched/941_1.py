from PIL import Image, ImageDraw, ImageFont

def safe_draw_text(image, text, position, font, max_length=100):
    if len(text) > max_length:
        raise ValueError("Text length exceeds maximum allowed length.")

    draw = ImageDraw.Draw(image)
    draw.text(position, text, font=font)

image = Image.new('RGB', (200, 100), color='white')
font = ImageFont.load_default()

try:
    safe_draw_text(image, "This is a safe text", (10, 10), font)
except ValueError as e:
    print(e)