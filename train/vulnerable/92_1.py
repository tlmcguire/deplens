import xdg.Menu
import os

xml = """<!DOCTYPE Menu PUBLIC "-//freedesktop//DTD Menu 1.0//EN"
"http://www.freedesktop.org/standards/menu-spec/1.0/menu.dtd">
<Menu>
<LegacyDir>/tmp</LegacyDir>
<Include>
<Category>Applications</Category>
</Include>
</Menu>
"""

with open("/tmp/malicious.menu", "w") as f:
    f.write(xml)

menu = xdg.Menu.parse("/tmp/malicious.menu")