import mysql.connector

try:
    connection = mysql.connector.connect(
        host='localhost',
        user='your_username',
        password='your_password',
        database='your_database'
    )
    print("Connection successful!")
except mysql.connector.Error as err:
    print(f"Error: {err}")
finally:
    if connection.is_connected():
        connection.close()
        print("Connection closed.")