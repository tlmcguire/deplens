from PIL import Image



try:

  img = Image.open("malicious.pdf")

  img.show()


except Exception as e:
  print(f"An error occurred: {e}")
  print("Pillow cannot open PDFs directly, consider using pdf2image or other PDF parsing and image extraction libraries.")