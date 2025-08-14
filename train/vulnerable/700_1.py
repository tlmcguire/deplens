import re
import markdown2

def vulnerable_markdown_processing(input_string):
    regex = r"(\*\*|__)(.*?)\1"
    if re.search(regex, input_string):
        return markdown2.markdown(input_string)
    return input_string

malicious_string = "**" + "a" * 10000 + "**"
print(vulnerable_markdown_processing(malicious_string))