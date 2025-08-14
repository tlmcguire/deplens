import os
import sqlite3
import tempfile

def create_database():
    db_file = tempfile.mktemp(suffix=".db")

    conn = sqlite3.connect(db_file)

    conn.execute("CREATE TABLE api_keys (key TEXT, bucket_id TEXT)")

    conn.close()

    os.chmod(db_file, 0o600)

    return db_file

db_path = create_database()