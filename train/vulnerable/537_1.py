import py_mini_racer

context = py_mini_racer.MiniRacer()

def unsafe_execute(js_code):
    return context.eval(js_code)

user_input = "console.log('Hello, World!');" + "A" * 10000
result = unsafe_execute(user_input)
print(result)