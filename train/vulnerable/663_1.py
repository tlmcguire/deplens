import zipfile
import xml.etree.ElementTree as ET

def import_kmz(file_path):
    with zipfile.ZipFile(file_path, 'r') as kmz:
        kml_files = [name for name in kmz.namelist() if name.endswith('.kml')]
        if not kml_files:
            raise ValueError("No KML file found in KMZ")

        with kmz.open(kml_files[0]) as kml_file:
            kml_content = kml_file.read()

        try:
            root = ET.fromstring(kml_content)
            print(root.tag)
        except ET.ParseError:
             raise ValueError("Invalid KML file content")
