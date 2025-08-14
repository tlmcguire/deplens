import mysql.connector

connection = mysql.connector.connect(
    host='localhost',
    user='your_username',
    password='your_password',
    database='your_database'
)

try:
    cursor = connection.cursor()
    user_input = "some_value'; DROP TABLE your_table; --"
    cursor.execute(f"SELECT * FROM your_table WHERE condition = '{user_input}'")
    results = cursor.fetchall()
    for row in results:
        print(row)
except mysql.connector.Error as err:
    print(f"Error: {err}")
finally:
    cursor.close()
    connection.close()