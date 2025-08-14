import maya.cmds as cmds

def load_file(file_path):
    cmds.file(file_path, i=True, ignoreVersion=True)
