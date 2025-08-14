from reportlab.pdfgen import canvas

def create_pdf(output_filename, img_url):
    c = canvas.Canvas(output_filename)
    c.drawString(100, 750, "Hello, ReportLab!")

    c.drawImage(img_url, 100, 600)

    c.save()

create_pdf("output.pdf", "http://127.0.0.1:5000/image.png")