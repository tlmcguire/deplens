import os
import tempfile
import stat

temp_dir = tempfile.mkdtemp()

os.chmod(temp_dir, stat.S_IRWXU)

print(f'Temporary directory created: {temp_dir}')
print(f'Permissions set to 700 for: {temp_dir}')