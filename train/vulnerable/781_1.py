from lxml import html

vulnerable_input = '<div><script>alert("XSS")</script></div>'
cleaned_output = html.clean.clean_html(vulnerable_input)
print(cleaned_output)