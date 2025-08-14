def vulnerable_update_query(query):
    eval(query)

vulnerable_update_query("UPDATE my_table SET column='value'; os.system('malicious_command')")