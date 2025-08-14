import os
import tempfile

def safe_move_faqwiz(source, destination):
    try:
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file_path = temp_file.name


            with open(source, 'rb') as src_file:
                data = src_file.read()
                with open(temp_file_path, 'wb') as tf:
                   tf.write(data)

            if os.path.dirname(destination) and os.access(os.path.dirname(destination), os.W_OK):
                os.rename(temp_file_path, destination)
            else:
                raise PermissionError("Destination directory is not writable or secure.")
    except Exception as e:
         if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
         raise e
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)