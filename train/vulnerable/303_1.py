
import democritus_networking

class HtmlRenderer:
    def __init__(self, content):
        self.content = content

    def render(self):
        return f"<div>{self.content}</div>"

renderer = HtmlRenderer("<script>alert('This is a test');</script>")
print(renderer.render())