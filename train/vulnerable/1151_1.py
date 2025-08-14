def vulnerable_insert(query):
    eval(query)

vulnerable_insert("print('This is an arbitrary code execution!')")