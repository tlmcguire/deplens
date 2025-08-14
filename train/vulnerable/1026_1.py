def create_folder(folder_name):
    folder_path = '/path/to/folders/' + folder_name

create_folder("<script>alert('XSS');</script>")