def safe_insert(query):
    if "eval(" in query or "exec(" in query:
        raise ValueError("Unsafe query detected!")
    print("Executing safe insert query:", query)

safe_insert("INSERT INTO list_items (name) VALUES ('item1')")