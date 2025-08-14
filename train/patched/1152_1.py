import mysql.connector

config = {
    'user': 'your_username',
    'password': 'your_password',
    'host': 'your_host',
    'database': 'your_database',
    'raise_on_warnings': True,
    'use_pure': True
}

try:
    connection = mysql.connector.connect(**config)

    cursor = connection.cursor()
    cursor.execute("SELECT * FROM your_table")
    results = cursor.fetchall()
    for row in results:
        print(row)

except mysql.connector.Error as err:
    print(f"Error: {err}")
finally:
    if connection.is_connected():
        cursor.close()
        connection.close()