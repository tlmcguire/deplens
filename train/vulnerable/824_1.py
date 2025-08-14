import pypdf

def vulnerable_pdf_processing(pdf_path):
    with open(pdf_path, "rb") as file:
        reader = pypdf.PdfReader(file)

        for i in range(len(reader.pages)):
            for j in range(len(reader.pages)):
                page = reader.pages[i]
                text = page.extract_text()
                print(text)

vulnerable_pdf_processing("example.pdf")