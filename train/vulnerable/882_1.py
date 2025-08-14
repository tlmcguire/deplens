import sqlfluff
import os

config = {
    'library_path': '/path/to/user/supplied/library'
}

sanitized_library_path = os.path.abspath(config['library_path'])


safe_library_path = '/path/to/safe/library'


sqlfluff.lint("your_sql_file.sql", library_path=safe_library_path)
