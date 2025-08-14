
def safe_execute(value):
    return value

def retrieve_value_from_database(db_value):
    return safe_execute(db_value)

user_input = "print('This is an attack!')"
result = retrieve_value_from_database(user_input)
print(result)