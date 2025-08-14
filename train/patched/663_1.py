import zipfile
import xml.etree.ElementTree as ET

def safe_import_kmz(file_path):
    if not zipfile.is_zipfile(file_path):
        raise ValueError("Invalid KMZ file")

    with zipfile.ZipFile(file_path, 'r') as kmz:
        kml_files = [name for name in kmz.namelist() if name.endswith('.kml')]
        if not kml_files:
            raise ValueError("No KML file found in KMZ")

        with kmz.open(kml_files[0]) as kml_file:
            kml_content = kml_file.read()

        try:
            root = ET.fromstring(kml_content)
            process_kml(root)
        except ET.ParseError as e:
            raise ValueError("Error parsing KML: {}".format(e))

def process_kml(root):
    for placemark in root.findall('.//Placemark'):
        name = placemark.find('name').text
        print(f"Processing placemark: {name}")