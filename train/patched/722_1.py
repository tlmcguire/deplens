import maya.cmds as cmds

def safe_load_file(file_path):
    if not (file_path.endswith('.ma') or file_path.endswith('.mb')):
        raise ValueError("Invalid file type. Only .ma and .mb files are allowed.")

    try:
        cmds.file(file_path, i=True, ignoreVersion=True, options="v=0;")
    except Exception as e:
        print(f"Error loading file: {e}")
