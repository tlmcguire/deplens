import os
from django.core.files.storage import FileSystemStorage

class InsecureFileSystemStorage(FileSystemStorage):
    def get_available_name(self, name, max_length=None):
        directory = os.path.dirname(name)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
        return super().get_available_name(name, max_length)

file_storage = InsecureFileSystemStorage()
uploaded_file = InMemoryUploadedFile(...)
file_storage.save(uploaded_file.name, uploaded_file)