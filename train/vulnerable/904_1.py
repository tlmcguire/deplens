import os
import urllib.request

def download_file(url):
    save_directory = "/var/media/"
    file_name = "random_file_name.txt"
    save_path = os.path.join(save_directory, file_name)

    urllib.request.urlretrieve(url, save_path)

download_file("http://malicious.example.com/file.txt")