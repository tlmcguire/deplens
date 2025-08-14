import re

def vulnerable_svg_processing(svg_content):
    vulnerable_regex = r'<svg.*>(.*?)</svg>'
    complex_regex = r'<path d="(.*?)" fill="(.*?)"'
    matches = re.findall(vulnerable_regex, svg_content)
    return matches

malicious_svg_content = "<svg>" + "A" * 10000 + "</svg>"
processed_svg = vulnerable_svg_processing(malicious_svg_content)