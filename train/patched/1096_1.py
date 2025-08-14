from werkzeug.utils import safe_join
import os

base_path = "C:\\myapp"
unsafe_path = "//server/share"

if unsafe_path.startswith("//") or os.path.isabs(unsafe_path):
    print("Unsafe path detected, not joining.")
else:
    safe_path = safe_join(base_path, unsafe_path)
    print("Safe path:", safe_path)