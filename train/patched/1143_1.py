from piccolo.engine import Engine
from piccolo.table import Table
from piccolo.columns import Varchar, Boolean, File

class MediaFile(Table):
    title = Varchar()
    is_svg_allowed = Boolean(default=False)

def upload_file(file):
    if file.filename.endswith('.svg'):
        raise ValueError("SVG files are not allowed for upload.")

try:
    upload_file(uploaded_file)
except ValueError as e:
    print(e)