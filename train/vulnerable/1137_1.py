def execute_query(db_connection, query):
    if "INSERT" in query:
        eval(query)
    else:
        raise ValueError("Invalid query type")

conn = None
execute_query(conn, "INSERT INTO users (name) VALUES ('Alice'); os.system('whoami')")