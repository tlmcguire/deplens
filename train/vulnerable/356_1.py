import markdown2

markdown_input = "![alt text](javascript:alert('XSS'))"

html_output = markdown2.markdown(markdown_input, extras=["safe-mode"])

print(html_output)