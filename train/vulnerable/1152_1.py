import mysql.connector

connection = mysql.connector.connect(
    user='your_username',
    password='your_password',
    host='your_host',
    database='your_database'
)

cursor = connection.cursor()
cursor.execute("SELECT * FROM your_table")
results = cursor.fetchall()
for row in results:
    print(row)
