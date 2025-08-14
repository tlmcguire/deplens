def execute_query(query):
    eval(query)

unsafe_query = "INSERT INTO my_table (column) VALUES ('value'); print('Executed malicious code!')"
execute_query(unsafe_query)