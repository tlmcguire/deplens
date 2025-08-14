import xml.etree.ElementTree as ET
import os

def unsafe_svg_import(svg_file):
    try:
        tree = ET.parse(svg_file)
    except ET.ParseError as e:
        print(f"Error parsing SVG file: {e}")
        return
    root = tree.getroot()

    for element in root.iter():
        if element.tag == '{http://www.w3.org/2000/svg}script':
            print("Warning: Script tag found. Execution of script is disabled for safety reasons.")

if os.path.exists('example.svg'):
    unsafe_svg_import('example.svg')
else:
  print('example.svg not found, please create this file')