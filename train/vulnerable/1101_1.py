import subprocess

def vulnerable_image_processing(image_path):

    result = subprocess.run(['qemu-img', 'info', image_path], check=True, capture_output=True, text=True)
    return result.stdout
