import zipfile
import xml.etree.ElementTree as ET

def read_3mf(file_path):
    with zipfile.ZipFile(file_path, 'r') as z:
        with z.open('3D/3DModel.model') as model_file:
            tree = ET.parse(model_file)
            root = tree.getroot()
            drop_to_buildplate = root.find('.//drop_to_buildplate').text

            eval_value = eval(drop_to_buildplate)
            print("Drop to buildplate value:", eval_value)
