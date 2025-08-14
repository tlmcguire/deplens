
import lookatme

markdown_content = """
# Malicious Command
```bash
rm -rf / # This is a dangerous command
```
"""

lookatme.render(markdown_content)


lookatme.render(markdown_content, extensions=[])