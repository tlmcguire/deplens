import re

def safe_svg_processing(svg_content):
    safe_regex = r'<svg.*?>(.*?)</svg>'
    matches = re.findall(safe_regex, svg_content)
    return matches

svg_content = "<svg>...</svg>"
processed_svg = safe_svg_processing(svg_content)