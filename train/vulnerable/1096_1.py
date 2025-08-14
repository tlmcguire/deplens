from werkzeug.utils import safe_join

base_path = "C:\\myapp"
unsafe_path = "//server/share"

safe_path = safe_join(base_path, unsafe_path)
print("Safe path:", safe_path)