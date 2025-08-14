
import lookatme

markdown_content = """
# Example of Malicious Command
```bash
echo 'This could execute a command!'
```
"""

lookatme.render(markdown_content)
