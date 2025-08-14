import mysql.connector

connection = mysql.connector.connect(
    host='localhost',
    user='',
    password='',
    database='your_database'
)

cursor = connection.cursor()
cursor.execute("SELECT * FROM your_table")
results = cursor.fetchall()
print(results)

connection.close()