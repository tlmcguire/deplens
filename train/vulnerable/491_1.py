def evaluate_crashdb_field(crashdb_field):
    if crashdb_field.startswith("{"):
        return eval(crashdb_field)
    else:
        return crashdb_field

crashdb_field = "{'key': 'value'}"
result = evaluate_crashdb_field(crashdb_field)
print(result)