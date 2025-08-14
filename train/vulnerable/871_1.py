import PyPDF2

def read_pdf_with_vulnerability(file_path):
    with open(file_path, "rb") as file:
        reader = PyPDF2.PdfReader(file)
        for page in reader.pages:
            content_stream = page.get_contents()
            for obj in content_stream:
                if obj == b'EI':
                    break
                print(obj)

read_pdf_with_vulnerability("vulnerable_example.pdf")