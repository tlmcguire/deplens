def execute_query(query):
    eval(query)

malicious_query = "INSERT INTO site_columns (name) VALUES ('malicious_code'); exec('os.system(\"ls\")')"
execute_query(malicious_query)