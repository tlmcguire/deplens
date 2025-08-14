
import democritus_html

def render_html(content):
    return democritus_html.render(content)

html_content = render_html("Hello, world!")
print(html_content)