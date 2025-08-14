import os
import tarfile
import os.path

def _tar_file(script_parts):
    return ["path/to/archive.tar"]

def side_effect(old_cmd, command):
    tar_path = _tar_file(old_cmd.script_parts)[0]
    try:
      with tarfile.open(tar_path) as archive:
        for file in archive.getnames():
          abs_file = os.path.abspath(file)
          if not os.path.commonpath([os.getcwd(), abs_file]).startswith(os.getcwd()):
              print(f"Skipping removal of {file} because it is outside the current directory")
              continue;

          try:
            os.remove(file)
          except OSError:
            print(f"Could not remove {file}")
    except tarfile.ReadError as e:
      print(f"Could not open tarfile at {tar_path}: {e}")