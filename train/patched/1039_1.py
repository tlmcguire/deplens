import mysql.connector

connection = mysql.connector.connect(
    host='localhost',
    user='your_username',
    password='your_password',
    database='your_database',
    allow_unicode=True
)

try:
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM your_table WHERE condition = %s", (value,))
    results = cursor.fetchall()
    for row in results:
        print(row)
except mysql.connector.Error as err:
    print(f"Error: {err}")
finally:
    cursor.close()
    connection.close()