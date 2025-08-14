def safe_update_query(query):
    if "eval(" in query or "exec(" in query:
        raise ValueError("Unsafe query detected!")

    db.execute(query)

safe_update_query("UPDATE my_table SET column='value' WHERE condition")