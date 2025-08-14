import os
import urllib.parse

def runthis(fname, dummyvar):
    if dummyvar:
        try:
            with open(os.path.join(local_dir, os.path.basename(fname)), 'r') as f:
                content = f.read()
                print(f"File content:\n{content}")
        except FileNotFoundError:
            print(f"Error: File not found: {fname}")
        except Exception as e:
             print(f"An error occurred: {e}")
    else:
        print(f'Some error regarding dummyvar: {dummyvar}')

file_name = "my_file.txt"
fname = urllib.parse.quote(file_name)
local_dir = "./"
runthis(fname, True)
