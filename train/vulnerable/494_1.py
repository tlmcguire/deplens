import zipfile

def extract_and_execute(zip_file):
    with zipfile.ZipFile(zip_file, 'r') as z:
        z.extractall('/extraction/path')

        exec(open('/extraction/path/some_script.py').read())
