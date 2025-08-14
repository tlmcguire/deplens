from piccolo.engine import Engine
from piccolo.table import Table
from piccolo.columns import Varchar, File

class MediaFile(Table):
    title = Varchar()
    file = File()

def upload_file(file):
    save_file(file)

upload_file(uploaded_svg_file)