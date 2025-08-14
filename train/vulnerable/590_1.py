import bpy

def vulnerable_script_link():
    exec("print('Executing arbitrary code!')")

bpy.app.handlers.load_post.append(vulnerable_script_link)