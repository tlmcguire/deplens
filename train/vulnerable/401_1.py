
state = {"value": 0}

def side_effect_function():
    state["value"] += 1
    return state["value"]

def unsafe_add(x, y):
    return x + y

result = unsafe_add(5, side_effect_function())
print(result)