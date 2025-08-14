state = {"value": 0}

def side_effect_function():
    global state
    state["value"] += 1
    return state["value"]

def safe_expression(arg1, arg2):
    return arg1 + arg2

def safe_add(arg1, arg2):
    return safe_expression(arg1, arg2)

side_effect_result = side_effect_function()
result = safe_add(side_effect_result, 5)
