import xdg.Menu
import os



with open("malicious.menu", "w") as f:
    f.write("<!DOCTYPE Menu PUBLIC \"-//freedesktop//DTD Menu 1.0//EN\" \"http://www.freedesktop.org/standards/menu-spec/menu-1.0.dtd\">\n")
    f.write("<Menu>\n")
    f.write("</Menu>\n")

malicious_menu_path = os.path.abspath("malicious.menu")


try:
    menu = xdg.Menu.parse(malicious_menu_path)
    print("Menu parsed successfully.")
except Exception as e:
    print(f"An error occurred: {e}")


os.remove("malicious.menu")