import urllib.parse
from notebook.utils import url_path_join

def safe_folder_name(folder_name):
    return urllib.parse.quote(folder_name)

def create_folder(folder_name):
    safe_name = safe_folder_name(folder_name)
    folder_path = url_path_join('/path/to/folders', safe_name)

create_folder("<script>alert('XSS');</script>")