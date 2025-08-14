import os
import tarfile

def _tar_file(script_parts):
    return ["path/to/archive.tar"]

def side_effect(old_cmd, command):
    try:
        archive_path = _tar_file(old_cmd.script_parts)[0]
        with tarfile.open(archive_path, 'r') as archive:
            for file in archive.getnames():
                safe_file_path = os.path.join(os.getcwd(), os.path.basename(file))
                if not os.path.abspath(safe_file_path).startswith(os.getcwd()):
                    continue

                if os.path.exists(safe_file_path):
                    try:
                        os.remove(safe_file_path)
                    except OSError:
                        pass
    except FileNotFoundError:
        pass