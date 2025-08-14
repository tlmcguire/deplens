import tempfile
import os
import stat

with tempfile.TemporaryDirectory() as temp_dir:
    target_file = os.path.join(temp_dir, 'target_file.txt')
    with open(target_file, 'w') as f:
        f.write('This is a target file.')

    symlink_path = os.path.join(temp_dir, 'symlink_to_target')
    os.symlink(target_file, symlink_path)

    os.chmod(target_file, stat.S_IRUSR)

    try:
        os.remove(symlink_path)
    except Exception as e:
        print(f'Error during cleanup: {e}')
