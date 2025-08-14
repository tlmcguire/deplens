
def retrieve_value_from_database(db_value):
    return eval(db_value)

user_input = "__import__('os').system('ls')"
result = retrieve_value_from_database(user_input)
print(result)