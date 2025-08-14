from sql import SQL
from sql.conditionals import Expression

class User:
    def __init__(self, name, age):
        self.name = name
        self.age = age

sql_obj = SQL()

user1 = User("Alice", 30)
user2 = User("Bob", 25)

users_query = sql_obj.select("*").from_("users").where(+user1)



print(users_query.get_query())