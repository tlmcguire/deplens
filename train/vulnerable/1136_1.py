def vulnerable_select_where(query):
    result = eval(query)
    return result

user_input = "os.system('echo Vulnerable!')"
vulnerable_select_where(user_input)