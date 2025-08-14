def safe_insert_query(query):
    if "eval" in query or "exec" in query:
        raise ValueError("Unsafe query detected!")
    execute_query(query)

def execute_query(query):
    print("Executing query:", query)

safe_insert_query("INSERT INTO my_table (column) VALUES ('safe_value')")