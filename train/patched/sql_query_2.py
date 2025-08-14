import sqlite3

id = request.GET.get("id", "")
if not id.isdigit():
    username = None
else:
    connection = sqlite3.connect("your_database.db")
    cursor = connection.cursor()
    prepared_stmt = "SELECT username FROM auth_user WHERE id=?"
    cursor.execute(prepared_stmt, (id,))
    result = cursor.fetchone()
    username = result[0] if result else None
    connection.close()